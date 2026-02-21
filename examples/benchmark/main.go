// Command benchmark is a BlazeHTTP server optimized for benchmarking with
// pre-allocated response bodies and zero-alloc handlers.
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blazehttp/blazehttp/server"
	"github.com/blazehttp/blazehttp/server/http2"
)

// Pre-allocated payloads for zero-alloc handlers.
var (
	plaintextBody = []byte("Hello, World!")
	jsonBody      = []byte(`{"message":"Hello, World!"}`)
	contentPlain  = []byte("text/plain")
	contentJSON   = []byte("application/json")
)

func handler(ctx *http2.RequestCtx) {
	switch string(ctx.Request.Path()) {
	case "/plaintext":
		ctx.SetStatusCode(200)
		ctx.Response.SetContentType(contentPlain)
		ctx.Response.SetBody(plaintextBody)
	case "/json":
		ctx.SetStatusCode(200)
		ctx.Response.SetContentType(contentJSON)
		ctx.Response.SetBody(jsonBody)
	default:
		ctx.SetStatusCode(404)
		ctx.SetBodyString("Not Found")
	}
}

func main() {
	cert, err := server.GenerateSelfSignedCert()
	if err != nil {
		log.Fatal(err)
	}

	s := &server.Server{
		Addr:    ":8443",
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		HTTP2: &server.HTTP2Config{
			MaxConcurrentStreams: 1000,
			InitialWindowSize:   1 << 20, // 1MB
		},
		WorkerPoolSize: 512,
	}

	go func() {
		fmt.Println("Benchmark server listening on https://localhost:8443")
		fmt.Println("  /plaintext — text/plain response")
		fmt.Println("  /json      — application/json response")
		if err := s.ListenAndServeTLS(); err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	s.Close()
	fmt.Println("Shutdown complete.")
}
