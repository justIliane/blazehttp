package client

import (
	"errors"
	"sync"
	"time"

	"github.com/blazehttp/blazehttp/client/h2fingerprint"
	blazetls "github.com/blazehttp/blazehttp/client/tls"
	"github.com/blazehttp/blazehttp/pkg/stream"
)

// ErrPoolClosed is returned when an operation is attempted on a closed pool.
var ErrPoolClosed = errors.New("client: connection pool closed")

// poolConn wraps a ClientConn with pool metadata.
type poolConn struct {
	cc        *ClientConn
	addr      string
	createdAt time.Time
}

// ConnPool manages a pool of HTTP/2 connections with transparent multiplexing.
// It auto-scales connections when existing ones are saturated, detects dead
// connections, and handles GOAWAY gracefully.
type ConnPool struct {
	mu      sync.Mutex
	cond    *sync.Cond
	conns   map[string][]*poolConn
	dialing map[string]int // in-flight dials per address

	dialer    *blazetls.TLSDialer
	h2Profile *h2fingerprint.H2Profile
	dialFunc  func(addr string, dialer *blazetls.TLSDialer, profile *h2fingerprint.H2Profile) (*ClientConn, error)

	maxConnsPerHost int
	maxIdlePerHost  int
	healthInterval  time.Duration
	dialTimeout     time.Duration
	waitTimeout     time.Duration

	done      chan struct{}
	closeOnce sync.Once
}

// PoolOption configures a ConnPool.
type PoolOption func(*ConnPool)

// WithMaxConnsPerHost sets the maximum number of connections per host.
func WithMaxConnsPerHost(n int) PoolOption {
	return func(p *ConnPool) { p.maxConnsPerHost = n }
}

// WithMaxIdlePerHost sets the maximum number of idle connections to keep per host.
func WithMaxIdlePerHost(n int) PoolOption {
	return func(p *ConnPool) { p.maxIdlePerHost = n }
}

// WithHealthCheckInterval sets the interval between health checks.
// Set to 0 to disable health checks.
func WithHealthCheckInterval(d time.Duration) PoolOption {
	return func(p *ConnPool) { p.healthInterval = d }
}

// WithDialTimeout sets the timeout for establishing new connections.
func WithDialTimeout(d time.Duration) PoolOption {
	return func(p *ConnPool) { p.dialTimeout = d }
}

// WithWaitTimeout sets the maximum time to wait for an available connection
// when all connections are saturated and the max connections limit is reached.
func WithWaitTimeout(d time.Duration) PoolOption {
	return func(p *ConnPool) { p.waitTimeout = d }
}

// NewConnPool creates a new connection pool.
func NewConnPool(dialer *blazetls.TLSDialer, profile *h2fingerprint.H2Profile, opts ...PoolOption) *ConnPool {
	p := &ConnPool{
		conns:           make(map[string][]*poolConn),
		dialing:         make(map[string]int),
		dialer:          dialer,
		h2Profile:       profile,
		maxConnsPerHost: 6,
		maxIdlePerHost:  2,
		healthInterval:  30 * time.Second,
		dialTimeout:     10 * time.Second,
		waitTimeout:     30 * time.Second,
		done:            make(chan struct{}),
	}
	p.cond = sync.NewCond(&p.mu)

	for _, opt := range opts {
		opt(p)
	}

	if p.healthInterval > 0 {
		go p.healthCheck()
	}

	return p
}

// pickConnLocked selects the least-loaded available connection for addr.
// Must be called with p.mu held.
func (p *ConnPool) pickConnLocked(addr string) *poolConn {
	conns := p.conns[addr]
	var best *poolConn
	bestActive := int(^uint(0) >> 1) // max int

	for _, pc := range conns {
		if pc.cc.IsClosed() || pc.cc.GoingAway() {
			continue
		}
		active := pc.cc.ActiveStreams()
		maxConcurrent := int(pc.cc.PeerSettings().MaxConcurrentStreams)
		if active >= maxConcurrent {
			continue
		}
		if active < bestActive {
			best = pc
			bestActive = active
		}
	}
	return best
}

// GetConn returns an available connection to addr, creating one if needed.
func (p *ConnPool) GetConn(addr string) (*ClientConn, error) {
	select {
	case <-p.done:
		return nil, ErrPoolClosed
	default:
	}

	p.mu.Lock()

	for {
		// Try to pick an existing connection.
		if pc := p.pickConnLocked(addr); pc != nil {
			p.mu.Unlock()
			return pc.cc, nil
		}

		// Clean up dead/going-away connections.
		p.cleanDeadLocked(addr)

		// Can we dial a new one?
		if len(p.conns[addr])+p.dialing[addr] < p.maxConnsPerHost {
			p.dialing[addr]++
			p.mu.Unlock()

			pc, err := p.dial(addr)
			if err != nil {
				p.mu.Lock()
				p.dialing[addr]--
				p.mu.Unlock()
				p.cond.Broadcast()
				return nil, err
			}

			p.mu.Lock()
			p.dialing[addr]--
			p.conns[addr] = append(p.conns[addr], pc)
			p.mu.Unlock()
			p.cond.Broadcast()
			return pc.cc, nil
		}

		// At max connections — wait for one to free up.
		waitDone := make(chan struct{})
		go func() {
			select {
			case <-time.After(p.waitTimeout):
				close(waitDone)
				p.cond.Broadcast()
			case <-p.done:
				close(waitDone)
				p.cond.Broadcast()
			}
		}()

		p.cond.Wait()

		// Check if pool was closed or timed out.
		select {
		case <-p.done:
			p.mu.Unlock()
			return nil, ErrPoolClosed
		case <-waitDone:
			p.mu.Unlock()
			return nil, errors.New("client: timed out waiting for available connection")
		default:
			// Retry — a connection may have freed up.
		}
	}
}

// dial creates a new connection to addr.
func (p *ConnPool) dial(addr string) (*poolConn, error) {
	var cc *ClientConn
	var err error
	if p.dialFunc != nil {
		cc, err = p.dialFunc(addr, p.dialer, p.h2Profile.Clone())
	} else {
		cc, err = Dial(addr, p.dialer, p.h2Profile.Clone())
	}
	if err != nil {
		return nil, err
	}
	return &poolConn{
		cc:        cc,
		addr:      addr,
		createdAt: time.Now(),
	}, nil
}

// roundTrip sends a request to addr and returns the response.
// It automatically retries on connection-level errors (GOAWAY, closed) and
// max-concurrent-streams saturation.
func (p *ConnPool) roundTrip(addr string, req *h2Request) (*h2Response, error) {
	const maxRetries = 3

	for attempt := 0; attempt <= maxRetries; attempt++ {
		cc, err := p.GetConn(addr)
		if err != nil {
			return nil, err
		}

		resp, err := cc.roundTrip(req)
		if err == nil {
			p.cond.Broadcast() // stream freed, wake waiters
			return resp, nil
		}

		// Retry on connection-level errors.
		if errors.Is(err, ErrGoAway) || errors.Is(err, ErrConnClosed) {
			p.removeConn(addr, cc)
			continue
		}

		// Retry on max concurrent streams exceeded (saturation race).
		if errors.Is(err, stream.ErrMaxConcurrentStreams) {
			// Connection was saturated between GetConn and writeLoop; retry.
			continue
		}

		// Stream-level errors (RST_STREAM, etc.) — no retry.
		return nil, err
	}

	return nil, errors.New("client: max retries exceeded")
}

// removeConn removes a specific connection from the pool and closes it.
func (p *ConnPool) removeConn(addr string, cc *ClientConn) {
	p.mu.Lock()
	conns := p.conns[addr]
	for i, pc := range conns {
		if pc.cc == cc {
			// Swap-delete.
			conns[i] = conns[len(conns)-1]
			p.conns[addr] = conns[:len(conns)-1]
			break
		}
	}
	p.mu.Unlock()

	cc.Close()
	p.cond.Broadcast()
}

// cleanDeadLocked removes closed/going-away connections from the pool for addr.
// Must be called with p.mu held. Does NOT close connections.
func (p *ConnPool) cleanDeadLocked(addr string) {
	conns := p.conns[addr]
	n := 0
	for _, pc := range conns {
		if !pc.cc.IsClosed() && !pc.cc.GoingAway() {
			conns[n] = pc
			n++
		}
	}
	// Nil out removed slots to avoid memory leaks.
	for i := n; i < len(conns); i++ {
		conns[i] = nil
	}
	p.conns[addr] = conns[:n]
}

// healthCheck periodically pings idle connections and removes dead ones.
func (p *ConnPool) healthCheck() {
	ticker := time.NewTicker(p.healthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.doHealthCheck()
		case <-p.done:
			return
		}
	}
}

// doHealthCheck runs a single health check pass.
func (p *ConnPool) doHealthCheck() {
	p.mu.Lock()
	// Snapshot all connections.
	var allConns []*poolConn
	for _, conns := range p.conns {
		allConns = append(allConns, conns...)
	}
	p.mu.Unlock()

	// Ping idle connections.
	for _, pc := range allConns {
		if pc.cc.ActiveStreams() == 0 && !pc.cc.IsClosed() {
			pc.cc.Ping()
		}
	}

	// Brief pause to let pings fail on dead sockets.
	time.Sleep(100 * time.Millisecond)

	// Remove dead and going-away connections.
	for _, pc := range allConns {
		if pc.cc.IsClosed() || pc.cc.GoingAway() {
			p.removeConn(pc.addr, pc.cc)
		}
	}

	// Trim excess idle connections.
	p.mu.Lock()
	for addr, conns := range p.conns {
		idle := 0
		for _, pc := range conns {
			if pc.cc.ActiveStreams() == 0 {
				idle++
			}
		}
		if idle > p.maxIdlePerHost {
			excess := idle - p.maxIdlePerHost
			// Remove from the end.
			newConns := make([]*poolConn, 0, len(conns))
			var toClose []*ClientConn
			removed := 0
			for i := len(conns) - 1; i >= 0; i-- {
				if removed < excess && conns[i].cc.ActiveStreams() == 0 {
					toClose = append(toClose, conns[i].cc)
					removed++
				} else {
					newConns = append(newConns, conns[i])
				}
			}
			p.conns[addr] = newConns
			p.mu.Unlock()
			for _, cc := range toClose {
				cc.Close()
			}
			p.mu.Lock()
		}
	}
	p.mu.Unlock()

	p.cond.Broadcast()
}

// Close shuts down the pool and all connections.
func (p *ConnPool) Close() error {
	p.closeOnce.Do(func() { close(p.done) })

	p.mu.Lock()
	var allConns []*poolConn
	for addr, conns := range p.conns {
		allConns = append(allConns, conns...)
		delete(p.conns, addr)
	}
	p.mu.Unlock()

	p.cond.Broadcast()

	for _, pc := range allConns {
		pc.cc.Close()
	}
	return nil
}

// ConnCount returns the number of connections to addr. For testing.
func (p *ConnPool) ConnCount(addr string) int {
	p.mu.Lock()
	n := len(p.conns[addr])
	p.mu.Unlock()
	return n
}
