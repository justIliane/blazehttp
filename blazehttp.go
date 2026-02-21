// Package blazehttp provides adapters between BlazeHTTP and the standard
// net/http ecosystem. It allows using net/http.Handler implementations with
// the BlazeHTTP server and vice versa.
package blazehttp

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/blazehttp/blazehttp/server/http2"
)

// WrapHandler adapts a standard net/http.Handler for use with BlazeHTTP.
// This enables using any existing http.Handler (e.g. from popular routers
// or middleware) with the high-performance BlazeHTTP server.
func WrapHandler(h http.Handler) http2.RequestHandler {
	return func(ctx *http2.RequestCtx) {
		// Build *http.Request from the BlazeHTTP request.
		method := string(ctx.Request.Method())
		path := string(ctx.Request.Path())

		var body io.Reader
		if b := ctx.Request.Body(); len(b) > 0 {
			body = bytes.NewReader(b)
		}

		req, err := http.NewRequest(method, path, body)
		if err != nil {
			ctx.SetStatusCode(500)
			ctx.SetBodyString("Internal Server Error")
			return
		}

		// Copy headers.
		for i := 0; i < ctx.Request.NumHeaders(); i++ {
			k, v := ctx.Request.HeaderAt(i)
			req.Header.Add(string(k), string(v))
		}

		// Set Host from :authority.
		if auth := ctx.Request.Authority(); len(auth) > 0 {
			req.Host = string(auth)
		}

		// Create a response writer.
		w := &responseWriter{header: make(http.Header), statusCode: 200}

		h.ServeHTTP(w, req)

		// Copy response back to BlazeHTTP context.
		ctx.SetStatusCode(w.statusCode)
		for k, vals := range w.header {
			for _, v := range vals {
				ctx.Response.SetHeader([]byte(k), []byte(v))
			}
		}
		ctx.SetBody(w.body.Bytes())
	}
}

// WrapBlazeHandler adapts a BlazeHTTP RequestHandler for use as a standard
// net/http.Handler. This allows embedding BlazeHTTP handlers in net/http
// servers or middleware chains.
func WrapBlazeHandler(h http2.RequestHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := http2.AcquireCtx()
		defer http2.ReleaseCtx(ctx)

		// Set pseudo-headers.
		ctx.Request.SetMethod([]byte(r.Method))
		ctx.Request.SetPath([]byte(r.URL.RequestURI()))
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		ctx.Request.SetScheme([]byte(scheme))
		if r.Host != "" {
			ctx.Request.SetAuthority([]byte(r.Host))
		}

		// Copy headers.
		for k, vals := range r.Header {
			for _, v := range vals {
				ctx.Request.AddHeader([]byte(k), []byte(v))
			}
		}

		// Copy body.
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err == nil && len(body) > 0 {
				ctx.Request.SetBody(body)
			}
		}

		// Call BlazeHTTP handler.
		h(ctx)

		// Write response.
		for i := 0; i < ctx.Response.NumHeaders(); i++ {
			k, v := ctx.Response.HeaderAt(i)
			w.Header().Set(string(k), string(v))
		}
		if body := ctx.Response.Body(); len(body) > 0 {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(ctx.Response.StatusCode())
		if body := ctx.Response.Body(); len(body) > 0 {
			w.Write(body)
		}
	})
}

// responseWriter implements http.ResponseWriter for the WrapHandler adapter.
type responseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}
