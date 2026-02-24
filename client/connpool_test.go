package client

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/justIliane/blazehttp/client/h2fingerprint"
	blazetls "github.com/justIliane/blazehttp/client/tls"
	"github.com/justIliane/blazehttp/pkg/frame"
	"github.com/justIliane/blazehttp/pkg/hpack"
	"github.com/justIliane/blazehttp/server/http2"
)

// testH2ServerPool starts a TLS+HTTP/2 server with enough worker capacity
// for pool tests (128 workers).
func testH2ServerPool(t testing.TB, handler http2.RequestHandler, settings ...http2.ConnSettings) (string, func()) {
	t.Helper()

	cert := testCertForTB(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	s := http2.DefaultServerSettings()
	if len(settings) > 0 {
		s = settings[0]
	}

	wp := http2.NewWorkerPool(128, handler)

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				http2.ServeConn(c, &http2.ConnConfig{
					Handler:    handler,
					WorkerPool: wp,
					Settings:   s,
				})
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		ln.Close()
		wg.Wait()
		wp.Stop()
	}

	return ln.Addr().String(), cleanup
}

func testCertForTB(tb testing.TB) tls.Certificate {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}

func testPool(t *testing.T, addr string, opts ...PoolOption) *ConnPool {
	t.Helper()
	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	defaultOpts := []PoolOption{WithHealthCheckInterval(0)} // disable health checks in tests by default
	opts = append(defaultOpts, opts...)
	return NewConnPool(dialer, profile, opts...)
}

func TestConnPool_Basic(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("pool-ok")
	})
	defer cleanup()

	pool := testPool(t, addr)
	defer pool.Close()

	resp, err := pool.roundTrip(addr, &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if string(resp.Body) != "pool-ok" {
		t.Errorf("body: got %q, want %q", resp.Body, "pool-ok")
	}
}

func TestConnPool_Multiplex100(t *testing.T) {
	var count atomic.Int64

	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		count.Add(1)
		// Small delay to keep streams active simultaneously.
		time.Sleep(10 * time.Millisecond)
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	})
	defer cleanup()

	pool := testPool(t, addr, WithMaxConnsPerHost(1))
	defer pool.Close()

	const N = 100
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := pool.roundTrip(addr, &h2Request{
				Method:    "GET",
				Scheme:    "https",
				Authority: "localhost",
				Path:      "/",
			})
			if err != nil {
				errs <- err
				return
			}
			if resp.StatusCode != 200 {
				errs <- fmt.Errorf("status: %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	if pool.ConnCount(addr) != 1 {
		t.Errorf("connections: got %d, want 1", pool.ConnCount(addr))
	}

	if count.Load() != N {
		t.Errorf("requests served: got %d, want %d", count.Load(), N)
	}
}

func TestConnPool_AutoScale(t *testing.T) {
	settings := http2.DefaultServerSettings()
	settings.MaxConcurrentStreams = 5

	var count atomic.Int64

	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		count.Add(1)
		time.Sleep(100 * time.Millisecond) // hold streams open long enough
		ctx.SetStatusCode(200)
	}, settings)
	defer cleanup()

	pool := testPool(t, addr, WithMaxConnsPerHost(4))
	defer pool.Close()

	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := pool.roundTrip(addr, &h2Request{
				Method:    "GET",
				Scheme:    "https",
				Authority: "localhost",
				Path:      "/",
			})
			if err != nil {
				errs <- err
				return
			}
			if resp.StatusCode != 200 {
				errs <- fmt.Errorf("status: %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	conns := pool.ConnCount(addr)
	if conns < 2 {
		t.Errorf("connections: got %d, want >= 2 (auto-scaled)", conns)
	}
}

func TestConnPool_GOAWAY(t *testing.T) {
	// Raw TLS server that sends GOAWAY after the first request.
	cert := testCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	defer ln.Close()

	var requestCount atomic.Int64

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fr := frame.AcquireFrameReader(conn)
				fw := frame.AcquireFrameWriter(conn)
				defer frame.ReleaseFrameReader(fr)
				defer frame.ReleaseFrameWriter(fw)

				enc := hpack.AcquireEncoder()
				defer hpack.ReleaseEncoder(enc)

				if err := rawServerHandshake(conn, fr, fw); err != nil {
					return
				}

				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if f.Type == frame.FrameHeaders {
						n := requestCount.Add(1)
						streamID := f.StreamID

						// Send response.
						hdr := enc.Encode([]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}})
						fw.WriteHeaders(streamID, true, hdr, nil)
						fw.Flush()

						if n == 1 {
							// Send GOAWAY after first request.
							time.Sleep(10 * time.Millisecond)
							fw.WriteGoAway(streamID, frame.ErrCodeNoError, nil)
							fw.Flush()
						}
					}
				}
			}(conn)
		}
	}()

	pool := testPool(t, addr)
	defer pool.Close()

	// First request succeeds.
	resp, err := pool.roundTrip(addr, &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/first",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("first request: got %d, want 200", resp.StatusCode)
	}

	// Give time for GOAWAY to be processed.
	time.Sleep(50 * time.Millisecond)

	// Second request should succeed via a new connection (retry).
	resp, err = pool.roundTrip(addr, &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/second",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("second request: got %d, want 200", resp.StatusCode)
	}
}

func TestConnPool_DeadConnection(t *testing.T) {
	// Raw server where we can close the connection on demand.
	cert := testCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	defer ln.Close()

	// Channel to signal we want the server to kill the connection.
	kill := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fr := frame.AcquireFrameReader(conn)
				fw := frame.AcquireFrameWriter(conn)
				defer frame.ReleaseFrameReader(fr)
				defer frame.ReleaseFrameWriter(fw)

				enc := hpack.AcquireEncoder()
				defer hpack.ReleaseEncoder(enc)

				if err := rawServerHandshake(conn, fr, fw); err != nil {
					return
				}

				for {
					select {
					case <-kill:
						// Close the connection to simulate dead server.
						return
					default:
					}

					conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					f, err := fr.ReadFrame()
					if err != nil {
						// Timeout, check kill again.
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							continue
						}
						return
					}
					conn.SetReadDeadline(time.Time{})

					if f.Type == frame.FrameHeaders {
						hdr := enc.Encode([]hpack.HeaderField{{Name: []byte(":status"), Value: []byte("200")}})
						fw.WriteHeaders(f.StreamID, true, hdr, nil)
						fw.Flush()
					} else if f.Type == frame.FramePing && !f.Flags.Has(frame.FlagACK) {
						fw.WritePing(true, f.PingData)
						fw.Flush()
					}
				}
			}(conn)
		}
	}()

	pool := testPool(t, addr, WithHealthCheckInterval(50*time.Millisecond), WithMaxIdlePerHost(5))
	defer pool.Close()

	// Establish connection.
	resp, err := pool.roundTrip(addr, &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	if pool.ConnCount(addr) != 1 {
		t.Fatalf("connections before kill: got %d, want 1", pool.ConnCount(addr))
	}

	// Kill the server-side connection.
	close(kill)

	// Wait for health check to detect the dead connection.
	time.Sleep(500 * time.Millisecond)

	if pool.ConnCount(addr) != 0 {
		t.Errorf("connections after kill: got %d, want 0", pool.ConnCount(addr))
	}
}

func TestConnPool_Close(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	pool := testPool(t, addr)

	// Establish connection.
	_, err := pool.roundTrip(addr, &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err != nil {
		t.Fatal(err)
	}

	pool.Close()

	// Subsequent operations should return ErrPoolClosed.
	_, err = pool.GetConn(addr)
	if err != ErrPoolClosed {
		t.Errorf("GetConn after Close: got %v, want ErrPoolClosed", err)
	}

	_, err = pool.roundTrip(addr, &h2Request{
		Method: "GET",
		Scheme: "https",
		Path:   "/",
	})
	if err != ErrPoolClosed {
		t.Errorf("RoundTrip after Close: got %v, want ErrPoolClosed", err)
	}
}

func TestConnPool_HealthCheckTrimsIdle(t *testing.T) {
	// Use a server with very low MaxConcurrentStreams to force multiple connections.
	settings := http2.DefaultServerSettings()
	settings.MaxConcurrentStreams = 1

	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		time.Sleep(200 * time.Millisecond) // hold stream open
		ctx.SetStatusCode(200)
	}, settings)
	defer cleanup()

	pool := testPool(t, addr,
		WithMaxConnsPerHost(5),
		WithMaxIdlePerHost(1),
		WithHealthCheckInterval(100*time.Millisecond),
	)
	defer pool.Close()

	// Send 3 concurrent requests — with MaxConcurrentStreams=1,
	// this forces 3 connections.
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.roundTrip(addr, &h2Request{
				Method:    "GET",
				Scheme:    "https",
				Authority: "localhost",
				Path:      "/",
			})
		}()
	}
	wg.Wait()

	// Now all 3 connections are idle. Wait for health check to trim.
	time.Sleep(300 * time.Millisecond)

	count := pool.ConnCount(addr)
	if count > 1 {
		t.Errorf("connections after trim: got %d, want <= 1", count)
	}
}

func TestConnPool_StreamResetNoRetry(t *testing.T) {
	// Raw server that sends RST_STREAM.
	cert := testCert(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fr := frame.AcquireFrameReader(conn)
				fw := frame.AcquireFrameWriter(conn)
				defer frame.ReleaseFrameReader(fr)
				defer frame.ReleaseFrameWriter(fw)

				if err := rawServerHandshake(conn, fr, fw); err != nil {
					return
				}

				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if f.Type == frame.FrameHeaders {
						fw.WriteRSTStream(f.StreamID, frame.ErrCodeRefusedStream)
						fw.Flush()
					}
				}
			}(conn)
		}
	}()

	pool := testPool(t, addr)
	defer pool.Close()

	_, err = pool.roundTrip(addr, &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Connection should still be in the pool (not removed on stream error).
	if pool.ConnCount(addr) != 1 {
		t.Errorf("connections: got %d, want 1 (stream reset should not remove conn)", pool.ConnCount(addr))
	}
}

func TestConnPool_ConcurrentGetConn(t *testing.T) {
	addr, cleanup := testH2ServerPool(t, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	pool := testPool(t, addr)
	defer pool.Close()

	const N = 50
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := pool.roundTrip(addr, &h2Request{
				Method:    "GET",
				Scheme:    "https",
				Authority: "localhost",
				Path:      "/",
			})
			if err != nil {
				errs <- err
				return
			}
			if resp.StatusCode != 200 {
				errs <- fmt.Errorf("status: %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// --- Benchmarks ---

func BenchmarkConnPool_SingleConn(b *testing.B) {
	addr, cleanup := testH2ServerPool(b, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	})
	defer cleanup()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	pool := NewConnPool(dialer, profile,
		WithMaxConnsPerHost(1),
		WithHealthCheckInterval(0),
	)
	defer pool.Close()

	req := &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	}

	// Warm up.
	if _, err := pool.roundTrip(addr, req); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, err := pool.roundTrip(addr, req)
		if err != nil {
			b.Fatal(err)
		}
		if resp.StatusCode != 200 {
			b.Fatalf("status: %d", resp.StatusCode)
		}
	}
}

func BenchmarkConnPool_Parallel(b *testing.B) {
	addr, cleanup := testH2ServerPool(b, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	})
	defer cleanup()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).SetInsecureSkipVerify(true)
	profile := h2fingerprint.ChromeH2.Clone()
	pool := NewConnPool(dialer, profile,
		WithHealthCheckInterval(0),
	)
	defer pool.Close()

	req := &h2Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "localhost",
		Path:      "/",
	}

	// Warm up.
	if _, err := pool.roundTrip(addr, req); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := pool.roundTrip(addr, req)
			if err != nil {
				b.Fatal(err)
			}
			if resp.StatusCode != 200 {
				b.Fatalf("status: %d", resp.StatusCode)
			}
		}
	})
}
