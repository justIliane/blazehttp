// Command hello is a minimal BlazeHTTP server demonstrating HTTP/1.1 and HTTP/2
// support with a single handler and auto-generated TLS certificate.
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/justIliane/blazehttp/server"
	"github.com/justIliane/blazehttp/server/http2"
)

func handler(ctx *http2.RequestCtx) {
	ctx.SetStatusCode(200)
	ctx.SetContentType("text/plain")
	ctx.SetBodyString("Hello, World!")
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
	}

	go func() {
		fmt.Println("BlazeHTTP listening on https://localhost:8443")
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
