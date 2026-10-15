package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"go-ti/pkg/ratelimit"
)

func TestWaitAllowsBurstImmediately(t *testing.T) {
	limiter := ratelimit.New(6000) // effectively unconstrained

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for i := 0; i < 100; i++ {
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("Wait() #%d error = %v", i, err)
		}
	}
}

func TestWaitHonorsContextCancellation(t *testing.T) {
	limiter := ratelimit.NewBurst(1, 1) // one token, then 1/min refill

	ctx, cancel := context.WithCancel(context.Background())

	// Consume the single burst token.
	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("first Wait() error = %v", err)
	}

	// With the context canceled the next Wait must fail instead of blocking
	// for a whole minute.
	cancel()
	if err := limiter.Wait(ctx); err == nil {
		t.Fatal("second Wait() expected context error")
	}
}

func TestWaitBlocksUntilRefill(t *testing.T) {
	limiter := ratelimit.NewBurst(6000, 1) // fast refill, burst of one

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("first Wait() error = %v", err)
	}

	start := time.Now()
	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("second Wait() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Errorf("second Wait() returned too fast (%v), expected to wait for refill", elapsed)
	}
}

func TestNewClampsInvalidRates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	for _, rate := range []int{0, -5} {
		if err := ratelimit.New(rate).Wait(ctx); err != nil {
			t.Errorf("New(%d).Wait() error = %v", rate, err)
		}
	}
}
