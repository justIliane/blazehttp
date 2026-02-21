// Command fileserver serves static files from a directory using BlazeHTTP,
// with directory traversal protection.
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"mime"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/blazehttp/blazehttp/server"
	"github.com/blazehttp/blazehttp/server/http2"
)

var rootDir string

func handler(ctx *http2.RequestCtx) {
	if string(ctx.Request.Method()) != "GET" {
		ctx.SetStatusCode(405)
		ctx.SetBodyString("Method Not Allowed\n")
		return
	}

	reqPath := string(ctx.Request.Path())
	if reqPath == "/" {
		reqPath = "/index.html"
	}

	// Clean and validate the path to prevent directory traversal.
	cleaned := filepath.Clean(reqPath)
	if strings.Contains(cleaned, "..") {
		ctx.SetStatusCode(403)
		ctx.SetBodyString("Forbidden\n")
		return
	}

	fullPath := filepath.Join(rootDir, cleaned)

	// Ensure the resolved path is within rootDir.
	abs, err := filepath.Abs(fullPath)
	if err != nil || !strings.HasPrefix(abs, rootDir) {
		ctx.SetStatusCode(403)
		ctx.SetBodyString("Forbidden\n")
		return
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.SetStatusCode(404)
			ctx.SetBodyString("Not Found\n")
		} else {
			ctx.SetStatusCode(500)
			ctx.SetBodyString("Internal Server Error\n")
		}
		return
	}

	// Detect content type from file extension.
	ext := filepath.Ext(fullPath)
	ct := mime.TypeByExtension(ext)
	if ct == "" {
		ct = "application/octet-stream"
	}

	ctx.SetStatusCode(200)
	ctx.SetContentType(ct)
	ctx.SetBody(data)
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		log.Fatalf("invalid directory: %v", err)
	}
	rootDir = absDir

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
		fmt.Printf("File server serving %s on https://localhost:8443\n", rootDir)
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
