package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/justIliane/blazehttp/server"
	"github.com/justIliane/blazehttp/server/http1"
	"github.com/justIliane/blazehttp/server/http2"
)

// Pre-allocated payloads (zero allocs in handler).
var (
	plaintextBody = []byte("Hello, World!")
	jsonBody      = []byte(`{"message":"Hello, World!"}`)
	contentPlain  = []byte("text/plain")
	contentJSON   = []byte("application/json")
)

func h2Handler(ctx *http2.RequestCtx) {
	switch string(ctx.Request.Path()) {
	case "/plaintext":
		ctx.SetStatusCode(200)
		ctx.Response.SetContentType(contentPlain)
		ctx.Response.SetBody(plaintextBody)
	case "/json":
		ctx.SetStatusCode(200)
		ctx.Response.SetContentType(contentJSON)
		ctx.Response.SetBody(jsonBody)
	case "/echo":
		ctx.SetStatusCode(200)
		ctx.Response.SetContentType(contentPlain)
		ctx.Response.SetBody(ctx.Request.Body())
	default:
		ctx.SetStatusCode(404)
		ctx.SetBodyString("Not Found")
	}
}

func h1Handler(ctx *http1.RequestCtx) {
	switch string(ctx.Request.Path()) {
	case "/plaintext":
		ctx.Response.SetStatusCode(200)
		ctx.Response.SetContentType(contentPlain)
		ctx.Response.SetBody(plaintextBody)
	case "/json":
		ctx.Response.SetStatusCode(200)
		ctx.Response.SetContentType(contentJSON)
		ctx.Response.SetBody(jsonBody)
	case "/echo":
		ctx.Response.SetStatusCode(200)
		ctx.Response.SetContentType(contentPlain)
		ctx.Response.SetBody(ctx.Request.Body())
	default:
		ctx.Response.SetStatusCode(404)
		ctx.Response.SetBody([]byte("Not Found"))
	}
}

func main() {
	cert, err := server.GenerateSelfSignedCert()
	if err != nil {
		log.Fatal(err)
	}

	// HTTP/1.1 server on :8080
	h1Srv := &server.Server{
		Addr:           ":8080",
		Handler:        h2Handler,
		HTTP1Handler:   h1Handler,
		WorkerPoolSize: 512,
	}

	// HTTP/2 TLS server on :8443
	h2Srv := &server.Server{
		Addr:                ":8443",
		Handler:             h2Handler,
		MaxConcurrentStreams: 1000,
		WorkerPoolSize:      512,
	}

	go func() {
		if err := h1Srv.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "HTTP/1.1 server error: %v\n", err)
		}
	}()

	go func() {
		if err := h2Srv.ListenAndServeTLSCert(cert); err != nil {
			fmt.Fprintf(os.Stderr, "HTTP/2 server error: %v\n", err)
		}
	}()

	fmt.Println("BlazeHTTP listening on :8080 (HTTP/1.1) and :8443 (HTTP/2 TLS)")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	h1Srv.Close()
	h2Srv.Close()
	fmt.Println("Shutdown complete.")
}
