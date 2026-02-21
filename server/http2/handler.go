package http2

import (
	"net"
	"sync"
)

// RequestHandler is the function signature for handling HTTP/2 requests.
// The ctx is pooled and must not be retained after the handler returns.
type RequestHandler func(ctx *RequestCtx)

// RequestCtx holds the request, response, and connection context for a
// single HTTP/2 request. It is pooled via sync.Pool.
type RequestCtx struct {
	Request  Request
	Response Response

	remoteAddr net.Addr
	localAddr  net.Addr
	streamID   uint32
	conn       *serverConn
}

var ctxPool = sync.Pool{
	New: func() any { return &RequestCtx{} },
}

// AcquireCtx gets a RequestCtx from the pool, ready for use.
func AcquireCtx() *RequestCtx {
	return acquireCtx()
}

// ReleaseCtx returns a RequestCtx to the pool.
func ReleaseCtx(ctx *RequestCtx) {
	releaseCtx(ctx)
}

func acquireCtx() *RequestCtx {
	ctx := ctxPool.Get().(*RequestCtx)
	ctx.Request.Reset()
	ctx.Response.Reset()
	ctx.remoteAddr = nil
	ctx.localAddr = nil
	ctx.streamID = 0
	ctx.conn = nil
	return ctx
}

func releaseCtx(ctx *RequestCtx) {
	ctx.Request.Reset()
	ctx.Response.Reset()
	ctx.conn = nil
	ctx.remoteAddr = nil
	ctx.localAddr = nil
	ctxPool.Put(ctx)
}

// RemoteAddr returns the remote address of the client connection.
func (ctx *RequestCtx) RemoteAddr() net.Addr { return ctx.remoteAddr }

// LocalAddr returns the local address the connection is bound to.
func (ctx *RequestCtx) LocalAddr() net.Addr { return ctx.localAddr }

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

// WorkerPool is a fixed-size pool of goroutines that process HTTP/2 requests.
type WorkerPool struct {
	workCh  chan *RequestCtx
	handler RequestHandler
	wg      sync.WaitGroup
}

// NewWorkerPool creates and starts a worker pool with n goroutines.
func NewWorkerPool(n int, handler RequestHandler) *WorkerPool {
	wp := &WorkerPool{
		workCh:  make(chan *RequestCtx, n*4),
		handler: handler,
	}
	wp.wg.Add(n)
	for i := 0; i < n; i++ {
		go wp.worker()
	}
	return wp
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for ctx := range wp.workCh {
		wp.handler(ctx)
		if ctx.conn != nil {
			ctx.conn.enqueueResponse(ctx)
		}
	}
}

// Submit submits a request context for processing by a worker.
// Returns false if the pool is at capacity.
func (wp *WorkerPool) Submit(ctx *RequestCtx) bool {
	select {
	case wp.workCh <- ctx:
		return true
	default:
		return false
	}
}

// Stop signals all workers to stop and waits for them to finish.
func (wp *WorkerPool) Stop() {
	close(wp.workCh)
	wp.wg.Wait()
}
