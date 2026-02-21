package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/valyala/fasthttp"
)

var (
	plaintextBody = []byte("Hello, World!")
	jsonBody      = []byte(`{"message":"Hello, World!"}`)
)

func handler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/plaintext":
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBody(plaintextBody)
	case "/json":
		ctx.SetStatusCode(200)
		ctx.SetContentType("application/json")
		ctx.SetBody(jsonBody)
	case "/echo":
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/plain")
		ctx.SetBody(ctx.PostBody())
	default:
		ctx.SetStatusCode(404)
		ctx.SetBodyString("Not Found")
	}
}

func main() {
	srv := &fasthttp.Server{
		Handler: handler,
	}

	go func() {
		if err := srv.ListenAndServe(":8081"); err != nil {
			log.Fatal(err)
		}
	}()

	fmt.Println("fasthttp listening on :8081 (HTTP/1.1)")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	srv.Shutdown()
	fmt.Println("Shutdown complete.")
}
