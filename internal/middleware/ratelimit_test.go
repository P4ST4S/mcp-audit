package middleware

import (
	"testing"
	"time"
)

func TestRateLimiter_NilReceiver(t *testing.T) {
	var l *RateLimiter
	if !l.Allow("client1", "tool1") {
		t.Fatal("nil rate limiter should allow all requests")
	}
}

func TestRateLimiter_Disabled(t *testing.T) {
	l := NewRateLimiter(false, 5)
	for i := 0; i < 10; i++ {
		if !l.Allow("client1", "tool1") {
			t.Fatal("disabled rate limiter should allow all requests")
		}
	}
}

func TestRateLimiter_DefaultRequestsPerMinute(t *testing.T) {
	// If requestsPerMinute <= 0, it should default to 60.
	l := NewRateLimiter(true, 0)
	if l.requestsPerMinute != 60 {
		t.Fatalf("expected default requestsPerMinute to be 60, got %d", l.requestsPerMinute)
	}

	lNegative := NewRateLimiter(true, -10)
	if lNegative.requestsPerMinute != 60 {
		t.Fatalf("expected negative requestsPerMinute to default to 60, got %d", lNegative.requestsPerMinute)
	}
}

func TestRateLimiter_FirstNAllowed(t *testing.T) {
	n := 5
	l := NewRateLimiter(true, n)
	for i := 1; i <= n; i++ {
		if !l.Allow("client1", "tool1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
}

func TestRateLimiter_NPlusOneRejected(t *testing.T) {
	n := 5
	l := NewRateLimiter(true, n)
	for i := 1; i <= n; i++ {
		if !l.Allow("client1", "tool1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	// The (N+1)th request should be rejected
	if l.Allow("client1", "tool1") {
		t.Fatal("the (N+1)th request should be rejected")
	}
}

func TestRateLimiter_EmptyToolNameDefaults(t *testing.T) {
	l := NewRateLimiter(true, 1)
	// The first call with empty tool name is allowed
	if !l.Allow("client1", "") {
		t.Fatal("first call with empty tool name should be allowed")
	}
	// The second call with empty tool name is rejected
	if l.Allow("client1", "") {
		t.Fatal("second call with empty tool name should be rejected")
	}
}

func TestRateLimiter_IndependentCounters(t *testing.T) {
	n := 3
	l := NewRateLimiter(true, n)

	// Exhaust (client1, tool1)
	for i := 0; i < n; i++ {
		if !l.Allow("client1", "tool1") {
			t.Fatalf("exhaust client1 tool1 request %d should be allowed", i)
		}
	}
	if l.Allow("client1", "tool1") {
		t.Fatal("client1 tool1 should now be rejected")
	}

	// Verify (client2, tool1) is still allowed (independent client)
	if !l.Allow("client2", "tool1") {
		t.Fatal("client2 tool1 should be allowed (independent client counter)")
	}

	// Verify (client1, tool2) is still allowed (independent tool)
	if !l.Allow("client1", "tool2") {
		t.Fatal("client1 tool2 should be allowed (independent tool counter)")
	}
}

func TestRateLimiter_CounterReset(t *testing.T) {
	// Configure requestsPerMinute = 600 to yield a reliable refill window (100ms)
	// refill rate = 1 minute / 600 = 100ms
	l := NewRateLimiter(true, 600)

	// Exhaust the burst limit of 600 requests
	for i := 0; i < 600; i++ {
		if !l.Allow("client1", "tool1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// 601st call should be rejected
	if l.Allow("client1", "tool1") {
		t.Fatal("601st request should be rejected")
	}

	// Sleep for 150ms to allow at least 1 token to refill.
	// This is deterministic on slow CI runners since 600 calls execute in <1ms,
	// and 150ms is comfortably larger than the 100ms refill threshold.
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again after refill
	if !l.Allow("client1", "tool1") {
		t.Fatal("request should be allowed again after refill window")
	}
}
