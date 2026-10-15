// Package ratelimit provides a minimal token-bucket rate limiter.
// It is intentionally dependency-free.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter restricts the rate of operations using the token-bucket algorithm.
// It is safe for concurrent use.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration // time between token refills
	tokens   float64
	burst    float64
	last     time.Time
}

// New creates a limiter allowing ratePerMin operations per minute with a
// burst equal to the full minute budget (spent at once, then refilled
// continuously). Rates below 1 are clamped to 1.
func New(ratePerMin int) *Limiter {
	return NewBurst(ratePerMin, ratePerMin)
}

// NewBurst creates a limiter allowing ratePerMin operations per minute with
// an explicit burst size (maximum instantly available tokens).
func NewBurst(ratePerMin, burst int) *Limiter {
	if ratePerMin < 1 {
		ratePerMin = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		interval: time.Minute / time.Duration(ratePerMin),
		tokens:   float64(burst),
		burst:    float64(burst),
		last:     time.Now(),
	}
}

// Wait blocks until a token is available or ctx is done. It returns the
// context error (e.g. deadline exceeded) when the budget is exhausted before
// a token frees up.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last)
		if elapsed > 0 {
			l.tokens = min(l.burst, l.tokens+float64(elapsed)/float64(l.interval))
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) * float64(l.interval))
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
