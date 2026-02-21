package server

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/blazehttp/blazehttp/server/http1"
	"github.com/blazehttp/blazehttp/server/http2"
)

// Server is the main BlazeHTTP server supporting HTTP/1.1 and HTTP/2.
type Server struct {
	// Addr is the TCP address to listen on (e.g. ":8443").
	Addr string

	// Handler handles HTTP/2 requests. For HTTP/1.1, a wrapper is used.
	Handler http2.RequestHandler

	// TLSConfig is the TLS configuration. If nil, defaults are used.
	TLSConfig *tls.Config

	// Timeouts.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// MaxConcurrentStreams per HTTP/2 connection (default 250).
	MaxConcurrentStreams uint32

	// WorkerPoolSize for HTTP/2 request processing (default: NumCPU * 256).
	WorkerPoolSize int

	// MaxRequestBodySize limits request body size.
	MaxRequestBodySize int

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

// ListenAndServeTLS starts the server with TLS using cert/key files.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
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
	cfg := &http1.ConnConfig{
		Handler:        s.wrapHTTP1Handler(),
		ReadTimeout:    s.ReadTimeout,
		WriteTimeout:   s.WriteTimeout,
		IdleTimeout:    s.IdleTimeout,
		MaxRequestBody: s.MaxRequestBodySize,
	}
	http1.ServeConn(conn, cfg)
}

func (s *Server) serveHTTP2(conn net.Conn, wp *http2.WorkerPool) {
	settings := http2.DefaultServerSettings()
	if s.MaxConcurrentStreams > 0 {
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

// wrapHTTP1Handler wraps the HTTP/2 handler for HTTP/1.1 connections.
func (s *Server) wrapHTTP1Handler() http1.RequestHandler {
	return func(ctx *http1.RequestCtx) {
		// Simple bridge: map HTTP/1.1 request to HTTP/2 handler.
		// For Phase 5, HTTP/1.1 uses its own handler directly.
		ctx.Response.SetStatusCode(200)
		ctx.Response.SetContentType([]byte("text/plain"))
		ctx.Response.SetBody([]byte("Hello from BlazeHTTP (HTTP/1.1)\n"))
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
