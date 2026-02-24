package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/justIliane/blazehttp/server/http1"
	"github.com/justIliane/blazehttp/server/http2"
)

// HTTP2Config holds HTTP/2-specific server settings.
type HTTP2Config struct {
	// MaxConcurrentStreams per connection (default 250).
	MaxConcurrentStreams uint32
	// MaxFrameSize is the maximum frame payload size (default 16384).
	MaxFrameSize uint32
	// InitialWindowSize is the initial flow-control window (default 1MB).
	InitialWindowSize uint32
	// MaxHeaderListSize is the maximum header list size (default 1MB).
	MaxHeaderListSize uint32
}

// Server is the main BlazeHTTP server supporting HTTP/1.1 and HTTP/2.
type Server struct {
	// Addr is the TCP address to listen on (e.g. ":8443").
	Addr string

	// Handler handles requests. It uses the HTTP/2 RequestCtx type, which is
	// also used for HTTP/1.1 requests via an automatic bridge when HTTP1Handler
	// is nil. This enables a single handler for both protocols.
	Handler http2.RequestHandler

	// TLSConfig is the TLS configuration. Required for ListenAndServeTLS().
	// Must include at least one certificate and should set NextProtos to
	// []string{"h2", "http/1.1"} for HTTP/2 support.
	TLSConfig *tls.Config

	// ReadTimeout is the maximum duration for reading a request.
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration for writing a response.
	WriteTimeout time.Duration
	// IdleTimeout is the maximum time to wait for the next request on a keep-alive connection.
	IdleTimeout time.Duration

	// MaxRequestBodySize limits request body size (default 4MB).
	MaxRequestBodySize int

	// HTTP2 holds HTTP/2-specific settings. If nil, defaults are used.
	HTTP2 *HTTP2Config

	// MaxConcurrentStreams per HTTP/2 connection (default 250).
	// Deprecated: use HTTP2.MaxConcurrentStreams instead.
	MaxConcurrentStreams uint32

	// WorkerPoolSize for HTTP/2 request processing (default: NumCPU * 256).
	WorkerPoolSize int

	// HTTP1Handler optionally overrides the default HTTP/1.1 handler.
	// If nil, Handler is used via an automatic protocol bridge.
	HTTP1Handler http1.RequestHandler

	// Internal state.
	listener   net.Listener
	workerPool *http2.WorkerPool
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	done       chan struct{}
	started    bool
}

// ListenAndServe starts the server on the configured address using plain HTTP.
// Supports h2c (HTTP/2 over cleartext) via connection preface detection.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// ListenAndServeTLS starts the server with TLS using the pre-configured TLSConfig.
// TLSConfig must be set and must contain at least one certificate.
func (s *Server) ListenAndServeTLS() error {
	if s.TLSConfig == nil || len(s.TLSConfig.Certificates) == 0 {
		return errors.New("blazehttp: TLSConfig with at least one certificate is required")
	}
	tlsConfig := s.TLSConfig.Clone()
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(tls.NewListener(ln, tlsConfig))
}

// ListenAndServeTLSFiles starts the server with TLS using cert/key files.
func (s *Server) ListenAndServeTLSFiles(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	return s.ListenAndServeTLSCert(cert)
}

// ListenAndServeTLSCert starts the server with a pre-loaded TLS certificate.
func (s *Server) ListenAndServeTLSCert(cert tls.Certificate) error {
	tlsConfig := s.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig(cert)
	} else {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.Certificates = []tls.Certificate{cert}
		if len(tlsConfig.NextProtos) == 0 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		}
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	tlsLn := tls.NewListener(ln, tlsConfig)
	return s.Serve(tlsLn)
}

// Serve accepts connections from the listener and serves them.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.listener = ln
	s.done = make(chan struct{})
	s.conns = make(map[net.Conn]struct{})
	s.started = true
	s.mu.Unlock()

	// Initialize worker pool.
	poolSize := s.WorkerPoolSize
	if poolSize == 0 {
		poolSize = runtime.NumCPU() * 256
	}
	wp := http2.NewWorkerPool(poolSize, s.Handler)
	s.mu.Lock()
	s.workerPool = wp
	s.mu.Unlock()

	defer wp.Stop()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil // graceful shutdown
			default:
			}
			// Transient error.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}

		setConnOpts(conn)
		s.trackConn(conn)
		go s.serveConn(conn, wp)
	}
}

func (s *Server) serveConn(conn net.Conn, wp *http2.WorkerPool) {
	defer s.untrackConn(conn)
	defer conn.Close()

	tlsConn, isTLS := conn.(*tls.Conn)

	if isTLS {
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		state := tlsConn.ConnectionState()
		switch state.NegotiatedProtocol {
		case "h2":
			s.serveHTTP2(conn, wp)
		default:
			s.serveHTTP1(conn)
		}
	} else {
		// Plain connection: detect h2c.
		pc := newPeekConn(conn)
		if pc.isH2C() {
			s.serveHTTP2(pc, wp)
		} else {
			s.serveHTTP1(pc)
		}
	}
}

func (s *Server) serveHTTP1(conn net.Conn) {
	h := s.HTTP1Handler
	if h == nil {
		h = s.wrapHTTP1Handler()
	}
	cfg := &http1.ConnConfig{
		Handler:        h,
		ReadTimeout:    s.ReadTimeout,
		WriteTimeout:   s.WriteTimeout,
		IdleTimeout:    s.IdleTimeout,
		MaxRequestBody: s.MaxRequestBodySize,
	}
	http1.ServeConn(conn, cfg)
}

func (s *Server) serveHTTP2(conn net.Conn, wp *http2.WorkerPool) {
	settings := http2.DefaultServerSettings()
	if s.HTTP2 != nil {
		if s.HTTP2.MaxConcurrentStreams > 0 {
			settings.MaxConcurrentStreams = s.HTTP2.MaxConcurrentStreams
		}
		if s.HTTP2.MaxFrameSize > 0 {
			settings.MaxFrameSize = s.HTTP2.MaxFrameSize
		}
		if s.HTTP2.InitialWindowSize > 0 {
			settings.InitialWindowSize = s.HTTP2.InitialWindowSize
		}
		if s.HTTP2.MaxHeaderListSize > 0 {
			settings.MaxHeaderListSize = s.HTTP2.MaxHeaderListSize
		}
	} else if s.MaxConcurrentStreams > 0 {
		settings.MaxConcurrentStreams = s.MaxConcurrentStreams
	}
	cfg := &http2.ConnConfig{
		Handler:            s.Handler,
		WorkerPool:         wp,
		Settings:           settings,
		ReadTimeout:        s.ReadTimeout,
		WriteTimeout:       s.WriteTimeout,
		IdleTimeout:        s.IdleTimeout,
		MaxRequestBodySize: s.MaxRequestBodySize,
	}
	http2.ServeConn(conn, cfg)
}

// wrapHTTP1Handler creates an HTTP/1.1 handler that bridges to the unified
// HTTP/2 handler. It translates the HTTP/1.1 request into an HTTP/2 RequestCtx,
// calls s.Handler, then copies the response back.
func (s *Server) wrapHTTP1Handler() http1.RequestHandler {
	return func(ctx *http1.RequestCtx) {
		h2ctx := http2.AcquireCtx()
		defer http2.ReleaseCtx(h2ctx)

		// Set pseudo-headers from HTTP/1.1 request.
		h2ctx.Request.SetMethod(ctx.Request.Method())
		h2ctx.Request.SetPath(ctx.Request.Path())
		h2ctx.Request.SetScheme([]byte("http"))

		// Host header → :authority pseudo-header.
		if host := ctx.Request.Header([]byte("Host")); host != nil {
			h2ctx.Request.SetAuthority(host)
		}

		// Copy regular headers.
		for i := 0; i < ctx.Request.NumHeaders(); i++ {
			k, v := ctx.Request.HeaderByIndex(i)
			h2ctx.Request.AddHeader(k, v)
		}

		// Copy body.
		if body := ctx.Request.Body(); len(body) > 0 {
			h2ctx.Request.SetBody(body)
		}

		// Call the unified handler.
		s.Handler(h2ctx)

		// Copy response back to HTTP/1.1.
		ctx.Response.SetStatusCode(h2ctx.Response.StatusCode())
		for i := 0; i < h2ctx.Response.NumHeaders(); i++ {
			k, v := h2ctx.Response.HeaderAt(i)
			ctx.Response.SetHeader(k, v)
		}
		if body := h2ctx.Response.Body(); body != nil {
			ctx.Response.SetBody(body)
		}
	}
}

// Close gracefully shuts down the server.
func (s *Server) Close() error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	close(s.done)
	s.listener.Close()

	// Close all tracked connections.
	s.mu.Lock()
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()

	return nil
}

func (s *Server) trackConn(conn net.Conn) {
	s.mu.Lock()
	s.conns[conn] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrackConn(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

// peekConn wraps a net.Conn to allow peeking at initial bytes
// for h2c connection preface detection.
type peekConn struct {
	net.Conn
	br     *bufio.Reader
	peeked bool
	isH2c  bool
}

func newPeekConn(conn net.Conn) *peekConn {
	return &peekConn{
		Conn: conn,
		br:   bufio.NewReaderSize(conn, 64),
	}
}

// isH2C peeks at the first bytes to detect the HTTP/2 client preface.
func (pc *peekConn) isH2C() bool {
	if pc.peeked {
		return pc.isH2c
	}
	pc.peeked = true
	peeked, err := pc.br.Peek(24)
	if err != nil {
		return false
	}
	pc.isH2c = string(peeked) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	return pc.isH2c
}

// Read reads from the buffered reader, replaying any peeked bytes.
func (pc *peekConn) Read(p []byte) (int, error) {
	return pc.br.Read(p)
}

// WriteTo implements io.WriterTo for efficient copying.
func (pc *peekConn) WriteTo(w io.Writer) (int64, error) {
	return pc.br.WriteTo(w)
}
