package clavex

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// ── Retry policy ──────────────────────────────────────────────────────────────

// RetryPolicy configures automatic request retries with exponential backoff.
//
//	client, _ := clavex.New(base, clavex.WithRetry(clavex.RetryPolicy{
//	    MaxAttempts: 3,
//	    BaseDelay:   200 * time.Millisecond,
//	}))
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts including the first.
	// 1 means no retry (the default). Set to 3 for two retry attempts.
	MaxAttempts int
	// BaseDelay is the initial backoff interval. Doubles on each attempt.
	BaseDelay time.Duration
	// MaxDelay caps the exponential growth.
	MaxDelay time.Duration
	// RetryOn is the list of HTTP status codes that trigger a retry.
	// Defaults to [429, 502, 503, 504].
	RetryOn []int
}

// WithRetry configures automatic retries on transient errors.
func WithRetry(p RetryPolicy) Option {
	return func(c *Client) {
		if p.MaxAttempts <= 0 {
			p.MaxAttempts = 1
		}
		if p.BaseDelay == 0 {
			p.BaseDelay = 250 * time.Millisecond
		}
		if p.MaxDelay == 0 {
			p.MaxDelay = 30 * time.Second
		}
		if len(p.RetryOn) == 0 {
			p.RetryOn = []int{429, 502, 503, 504}
		}
		c.retry = p
	}
}

// shouldRetry reports whether the given HTTP status code warrants a retry.
func (p *RetryPolicy) shouldRetry(status int) bool {
	for _, s := range p.RetryOn {
		if s == status {
			return true
		}
	}
	return false
}

// sleep waits for the delay appropriate for the n-th retry attempt (0-based)
// with ±20% random jitter. Honors context cancellation.
func (p *RetryPolicy) sleep(ctx context.Context, attempt int) error {
	exp := p.BaseDelay
	for i := 0; i < attempt; i++ {
		exp *= 2
		if exp > p.MaxDelay {
			exp = p.MaxDelay
			break
		}
	}
	// ±20% jitter: exp ± (exp/5)
	window := int64(exp / 5)
	if window > 0 {
		jitter := time.Duration(rand.Int63n(window*2) - window)
		exp += jitter
	}
	if exp < 0 {
		exp = 0
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(exp):
		return nil
	}
}

// ── Circuit breaker ───────────────────────────────────────────────────────────

// CircuitBreakerConfig configures the circuit breaker that prevents
// cascading failures when the API is unavailable.
//
//	client, _ := clavex.New(base, clavex.WithCircuitBreaker(clavex.CircuitBreakerConfig{
//	    Threshold: 5,
//	    Timeout:   30 * time.Second,
//	}))
type CircuitBreakerConfig struct {
	// Threshold is the number of consecutive failures that open the circuit.
	// Defaults to 5.
	Threshold int
	// Timeout is how long the circuit stays open before a trial request is
	// allowed through (half-open state). Defaults to 30s.
	Timeout time.Duration
}

// WithCircuitBreaker enables the circuit breaker.
func WithCircuitBreaker(cfg CircuitBreakerConfig) Option {
	return func(c *Client) {
		if cfg.Threshold <= 0 {
			cfg.Threshold = 5
		}
		if cfg.Timeout <= 0 {
			cfg.Timeout = 30 * time.Second
		}
		c.cb = &circuitBreaker{cfg: cfg}
	}
}

// ErrCircuitOpen is returned when all requests are blocked by the circuit breaker.
type ErrCircuitOpen struct{}

func (ErrCircuitOpen) Error() string {
	return "clavex: circuit breaker is open — API appears unavailable"
}

type cbState int

const (
	cbClosed   cbState = iota // normal operation
	cbOpen                    // blocking all requests
	cbHalfOpen                // single trial request allowed
)

type circuitBreaker struct {
	mu        sync.Mutex
	cfg       CircuitBreakerConfig
	state     cbState
	failures  int
	openUntil time.Time
}

// allow returns true if a request should be allowed through.
func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbOpen:
		if time.Now().After(cb.openUntil) {
			cb.state = cbHalfOpen
			return true
		}
		return false
	default:
		return true
	}
}

// success records a successful call and resets the breaker.
func (cb *circuitBreaker) success() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = cbClosed
	cb.failures = 0
}

// failure records a failed call and may open the circuit.
func (cb *circuitBreaker) failure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.state == cbHalfOpen || cb.failures >= cb.cfg.Threshold {
		cb.state = cbOpen
		cb.openUntil = time.Now().Add(cb.cfg.Timeout)
		cb.failures = 0
	}
}
