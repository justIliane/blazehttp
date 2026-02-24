package blazehttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/justIliane/blazehttp/server/http2"
)

func TestWrapHandler(t *testing.T) {
	// Create a standard net/http handler.
	stdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "hello")
		w.WriteHeader(201)
		w.Write([]byte("created:" + r.URL.Path))
	})

	// Wrap it for BlazeHTTP.
	blazeHandler := WrapHandler(stdHandler)

	ctx := http2.AcquireCtx()
	defer http2.ReleaseCtx(ctx)

	ctx.Request.SetMethod([]byte("POST"))
	ctx.Request.SetPath([]byte("/test"))
	ctx.Request.SetScheme([]byte("https"))
	ctx.Request.SetAuthority([]byte("localhost"))

	blazeHandler(ctx)

	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("expected status 201, got %d", ctx.Response.StatusCode())
	}

	body := string(ctx.Response.Body())
	if body != "created:/test" {
		t.Fatalf("expected body 'created:/test', got %q", body)
	}
}

func TestWrapHandler_WithBody(t *testing.T) {
	stdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write([]byte("echo:" + string(body)))
	})

	blazeHandler := WrapHandler(stdHandler)

	ctx := http2.AcquireCtx()
	defer http2.ReleaseCtx(ctx)

	ctx.Request.SetMethod([]byte("POST"))
	ctx.Request.SetPath([]byte("/echo"))
	ctx.Request.SetScheme([]byte("https"))
	ctx.Request.SetBody([]byte("hello"))

	blazeHandler(ctx)

	if got := string(ctx.Response.Body()); got != "echo:hello" {
		t.Fatalf("expected 'echo:hello', got %q", got)
	}
}

func TestWrapBlazeHandler(t *testing.T) {
	// Create a BlazeHTTP handler.
	blazeHandler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		path := string(ctx.Request.Path())
		ctx.SetBodyString("path:" + path)
	}

	// Wrap it as net/http.Handler.
	stdHandler := WrapBlazeHandler(blazeHandler)

	// Use httptest to test it.
	req := httptest.NewRequest("GET", "/hello", nil)
	w := httptest.NewRecorder()

	stdHandler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	if string(body) != "path:/hello" {
		t.Fatalf("expected 'path:/hello', got %q", string(body))
	}
}

func TestWrapBlazeHandler_WithBody(t *testing.T) {
	blazeHandler := func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBody(ctx.Request.Body())
	}

	stdHandler := WrapBlazeHandler(blazeHandler)

	req := httptest.NewRequest("POST", "/echo", strings.NewReader("test body"))
	w := httptest.NewRecorder()

	stdHandler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != "test body" {
		t.Fatalf("expected 'test body', got %q", string(body))
	}
}
