package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

var (
	plaintextBody = []byte("Hello, World!")
	jsonBody      = []byte(`{"message":"Hello, World!"}`)
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/plaintext", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(plaintextBody)
	})

	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonBody)
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		buf := make([]byte, 0, 1024)
		tmp := make([]byte, 4096)
		for {
			n, err := r.Body.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		w.Write(buf)
	})

	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cert error: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:    ":8444",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		},
	}

	http2.ConfigureServer(srv, &http2.Server{
		MaxConcurrentStreams: 1000,
	})

	ln, err := net.Listen("tcp", ":8444")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)

	go func() {
		if err := srv.Serve(tlsLn); err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "net/http server error: %v\n", err)
		}
	}()

	fmt.Println("net/http listening on :8444 (HTTP/2 TLS)")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	srv.Close()
	fmt.Println("Shutdown complete.")
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Bench"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
