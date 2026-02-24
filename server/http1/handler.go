package http1

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"

	"github.com/justIliane/blazehttp/pkg/bytespool"
)

const (
	defaultReadBufSize = 4096
	defaultMaxBodySize = 4 * 1024 * 1024 // 4MB
)

// RequestHandler is the function signature for handling HTTP/1.1 requests.
// ctx is pooled and must not be retained after the handler returns.
type RequestHandler func(ctx *RequestCtx)

// RequestCtx holds the request, response, and connection context for a single
// HTTP/1.1 request. It is pooled via sync.Pool.
type RequestCtx struct {
	Request  Request
	Response Response

	// Connection information.
	remoteAddr net.Addr
	localAddr  net.Addr
	connID     uint64
}

var ctxPool = sync.Pool{
	New: func() any {
		return &RequestCtx{}
	},
}

func acquireCtx() *RequestCtx {
	return ctxPool.Get().(*RequestCtx)
}

func releaseCtx(ctx *RequestCtx) {
	ctx.Request.Reset()
	ctx.Response.Reset()
	ctx.remoteAddr = nil
	ctx.localAddr = nil
	ctx.connID = 0
	ctxPool.Put(ctx)
}

// RemoteAddr returns the remote address of the client connection.
func (ctx *RequestCtx) RemoteAddr() net.Addr {
	return ctx.remoteAddr
}

// LocalAddr returns the local address the connection is bound to.
func (ctx *RequestCtx) LocalAddr() net.Addr {
	return ctx.localAddr
}

// SetContentType is a convenience method for setting Content-Type.
func (ctx *RequestCtx) SetContentType(ct string) {
	ctx.Response.SetContentType([]byte(ct))
}

// SetStatusCode sets the HTTP response status code.
func (ctx *RequestCtx) SetStatusCode(code int) {
	ctx.Response.SetStatusCode(code)
}

// SetBody sets the response body.
func (ctx *RequestCtx) SetBody(body []byte) {
	ctx.Response.SetBody(body)
}

// SetBodyString sets the response body from a string.
func (ctx *RequestCtx) SetBodyString(s string) {
	ctx.Response.SetBodyString(s)
}

// ConnConfig holds configuration for an HTTP/1.1 connection handler.
type ConnConfig struct {
	Handler        RequestHandler
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxRequestBody int
}

// ServeConn serves HTTP/1.1 requests on the given connection.
// It implements the read loop with HTTP/1.1 pipelining support.
// The function returns when the connection should be closed.
func ServeConn(conn net.Conn, cfg *ConnConfig) error {
	if cfg.MaxRequestBody == 0 {
		cfg.MaxRequestBody = defaultMaxBodySize
	}

	br := bufio.NewReaderSize(conn, defaultReadBufSize)
	buf := bytespool.Get(defaultReadBufSize)
	defer bytespool.Put(buf)

	var connID uint64
	remoteAddr := conn.RemoteAddr()
	localAddr := conn.LocalAddr()

	for {
		// Set read timeout.
		if cfg.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(cfg.IdleTimeout))
		}

		// Read data into buffer.
		buf = buf[:cap(buf)]
		n, err := readUntilComplete(br, buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		data := buf[:n]

		// Reset read deadline for request processing.
		if cfg.ReadTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
		}

		// Parse and handle the request.
		ctx := acquireCtx()
		ctx.remoteAddr = remoteAddr
		ctx.localAddr = localAddr
		ctx.connID = connID
		connID++

		consumed, parseErr := ctx.Request.Parse(data)
		if parseErr != nil {
			// Send 400 Bad Request on parse errors.
			ctx.Response.SetStatusCode(400)
			ctx.Response.SetBody([]byte("Bad Request\n"))
			resp := ctx.Response.Build(false)
			if cfg.WriteTimeout > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
			}
			_, _ = conn.Write(resp)
			releaseCtx(ctx)
			return parseErr
		}

		// Call the handler.
		cfg.Handler(ctx)

		// Build and send the response.
		keepAlive := ctx.Request.IsKeepAlive()
		resp := ctx.Response.Build(keepAlive)

		if cfg.WriteTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
		}
		_, writeErr := conn.Write(resp)
		releaseCtx(ctx)

		if writeErr != nil {
			return writeErr
		}

		if !keepAlive {
			return nil
		}

		// Handle pipelined data: shift unconsumed bytes to the front.
		remaining := n - consumed
		if remaining > 0 {
			copy(buf, data[consumed:n])
		}
		buf = buf[:remaining]

		// For pipelined requests, we'd loop back and parse from buf.
		// For simplicity in Phase 1, we rely on the next read iteration.
		buf = buf[:cap(buf)]
	}
}

// readUntilComplete reads from r into buf, expanding it if needed,
// until we have a complete header section (contains \r\n\r\n).
func readUntilComplete(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for {
		if total >= len(buf) {
			// Grow the buffer.
			newBuf := bytespool.Get(len(buf) * 2)
			copy(newBuf, buf[:total])
			bytespool.Put(buf)
			buf = newBuf
		}

		n, err := r.Read(buf[total:])
		total += n

		// Check if we have the complete header section.
		if total >= 4 {
			// Search only in newly read area.
			searchStart := total - n
			if searchStart < 3 {
				searchStart = 0
			}
			for i := searchStart; i+3 < total; i++ {
				if buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n' {
					return total, nil
				}
			}
		}

		if err != nil {
			return total, err
		}
	}
}
