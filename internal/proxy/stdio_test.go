package proxy

import (
	"testing"
	"time"
)

func TestRPCStatePurgeExpired(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	state := newRPCState()

	state.rememberClient("client-expired", pendingCall{startedAt: now.Add(-31 * time.Second)})
	state.rememberClient("client-fresh", pendingCall{startedAt: now.Add(-29 * time.Second)})
	state.rememberServer("server-expired", pendingCall{startedAt: now.Add(-time.Minute)})
	state.rememberServer("server-fresh", pendingCall{startedAt: now})

	if got := state.purgeExpired(now, 30*time.Second); got != 2 {
		t.Fatalf("purged %d pending calls, want 2", got)
	}
	if _, ok := state.takeClient("client-expired"); ok {
		t.Fatal("expired client call was not purged")
	}
	if _, ok := state.takeServer("server-expired"); ok {
		t.Fatal("expired server call was not purged")
	}
	if _, ok := state.takeClient("client-fresh"); !ok {
		t.Fatal("fresh client call was purged")
	}
	if _, ok := state.takeServer("server-fresh"); !ok {
		t.Fatal("fresh server call was purged")
	}
}
