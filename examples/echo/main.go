// Command echo is a BlazeHTTP server that echoes the request body back in the
// response, demonstrating POST body handling.
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/blazehttp/blazehttp/server"
	"github.com/blazehttp/blazehttp/server/http2"
)

func handler(ctx *http2.RequestCtx) {
	switch string(ctx.Request.Method()) {
	case "POST", "PUT":
		ctx.SetStatusCode(200)
		ctx.SetContentType("application/octet-stream")
		ctx.SetBody(ctx.Request.Body())
	case "GET":
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBodyString("Send a POST request with a body to echo it back.\n")
	default:
		ctx.SetStatusCode(405)
		ctx.SetBodyString("Method Not Allowed\n")
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
		MaxRequestBodySize: 1 << 20, // 1MB
	}

	go func() {
		fmt.Println("Echo server listening on https://localhost:8443")
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
