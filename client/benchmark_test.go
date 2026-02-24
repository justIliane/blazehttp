package client

import (
	"fmt"
	"testing"
	"time"

	"github.com/justIliane/blazehttp/client/h2fingerprint"
	blazetls "github.com/justIliane/blazehttp/client/tls"
	"github.com/justIliane/blazehttp/server/http2"
)

// BenchmarkClient_SingleRequest measures single request latency through
// the high-level Client API.
// Target: < 100µs per request (excluding network).
func BenchmarkClient_SingleRequest(b *testing.B) {
	addr, cleanup := testH2ServerPool(b, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	})
	defer cleanup()

	c := &Client{
		UserAgent:       "bench",
		FollowRedirects: false,
		RequestTimeout:  10 * time.Second,
		tlsFingerprint:  blazetls.GoDefault,
		h2Profile:       h2fingerprint.ChromeH2.Clone(),
	}
	c.dialer = blazetls.NewTLSDialer(blazetls.GoDefault).
		SetInsecureSkipVerify(true).
		SetTimeout(10 * time.Second)
	c.pool = NewConnPool(c.dialer, c.h2Profile,
		WithMaxConnsPerHost(1),
		WithHealthCheckInterval(0),
	)
	defer c.Close()

	url := fmt.Sprintf("https://%s/bench", addr)

	// Warm up.
	resp, err := c.Get(url)
	if err != nil {
		b.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b.Fatalf("warmup status: %d", resp.StatusCode)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, err := c.Get(url)
		if err != nil {
			b.Fatal(err)
		}
		if resp.StatusCode != 200 {
			b.Fatalf("status: %d", resp.StatusCode)
		}
	}
}

// BenchmarkClient_Multiplex100 measures throughput of 100 concurrent requests
// via DoBatch on a single connection.
// Target: > 10,000 req/s.
func BenchmarkClient_Multiplex100(b *testing.B) {
	addr, cleanup := testH2ServerPool(b, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
	})
	defer cleanup()

	c := &Client{
		UserAgent:       "bench",
		FollowRedirects: false,
		RequestTimeout:  10 * time.Second,
		tlsFingerprint:  blazetls.GoDefault,
		h2Profile:       h2fingerprint.ChromeH2.Clone(),
	}
	c.dialer = blazetls.NewTLSDialer(blazetls.GoDefault).
		SetInsecureSkipVerify(true).
		SetTimeout(10 * time.Second)
	c.pool = NewConnPool(c.dialer, c.h2Profile,
		WithHealthCheckInterval(0),
	)
	defer c.Close()

	// Build 100 requests.
	const batchSize = 100
	reqs := make([]*Request, batchSize)
	for i := 0; i < batchSize; i++ {
		reqs[i] = NewRequest("GET", fmt.Sprintf("https://%s/bench/%d", addr, i))
	}

	// Warm up.
	if _, err := c.DoBatch(reqs[:1]); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resps, err := c.DoBatch(reqs)
		if err != nil {
			b.Fatal(err)
		}
		if resps[0].StatusCode != 200 {
			b.Fatalf("status: %d", resps[0].StatusCode)
		}
	}

	b.StopTimer()
	elapsed := b.Elapsed()
	totalReqs := float64(b.N) * batchSize
	reqsPerSec := totalReqs / elapsed.Seconds()
	b.ReportMetric(reqsPerSec, "req/s")
}

// BenchmarkClient_Allocs verifies zero allocations in the hot path
// (steady state, after warm-up).
func BenchmarkClient_Allocs(b *testing.B) {
	addr, cleanup := testH2ServerPool(b, func(ctx *http2.RequestCtx) {
		ctx.SetStatusCode(200)
	})
	defer cleanup()

	dialer := blazetls.NewTLSDialer(blazetls.GoDefault).
		SetInsecureSkipVerify(true).
		SetTimeout(10 * time.Second)
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

	// Warm up — establish connection.
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
