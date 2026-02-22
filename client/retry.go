package client

import (
	"math"
	"math/rand"
	"time"
)

// RetryConfig configures retry behavior with exponential backoff.
type RetryConfig struct {
	MaxRetries   int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       float64
	RetryOn      []int  // status codes to retry on
	RetryOnError bool   // retry on connection errors
}

// DefaultRetryConfig returns sensible retry defaults.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:   3,
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1,
		RetryOn:      []int{429, 500, 502, 503, 504},
		RetryOnError: true,
	}
}

// shouldRetry returns true if the request should be retried.
func (rc *RetryConfig) shouldRetry(resp *Response, err error) bool {
	if err != nil {
		return rc.RetryOnError
	}
	if resp != nil {
		for _, code := range rc.RetryOn {
			if resp.StatusCode == code {
				return true
			}
		}
	}
	return false
}

// delay returns the backoff duration for the given attempt (0-indexed).
func (rc *RetryConfig) delay(attempt int) time.Duration {
	d := float64(rc.InitialDelay) * math.Pow(rc.Multiplier, float64(attempt))
	if d > float64(rc.MaxDelay) {
		d = float64(rc.MaxDelay)
	}
	// Apply jitter.
	if rc.Jitter > 0 {
		jitter := d * rc.Jitter
		d += (rand.Float64()*2 - 1) * jitter
	}
	return time.Duration(d)
}
