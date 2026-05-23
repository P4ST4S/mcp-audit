package middleware

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter applies per-client, per-tool token buckets.
type RateLimiter struct {
	mu                sync.Mutex
	enabled           bool
	requestsPerMinute int
	limiters          map[string]*rate.Limiter
}

// NewRateLimiter creates a per-tool rate limiter.
func NewRateLimiter(enabled bool, requestsPerMinute int) *RateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 60
	}
	return &RateLimiter{
		enabled:           enabled,
		requestsPerMinute: requestsPerMinute,
		limiters:          make(map[string]*rate.Limiter),
	}
}

// Allow reports whether clientID may call toolName now.
func (l *RateLimiter) Allow(clientID, toolName string) bool {
	if l == nil || !l.enabled {
		return true
	}
	if toolName == "" {
		toolName = "unknown"
	}
	key := fmt.Sprintf("%s:%s", clientID, toolName)
	l.mu.Lock()
	limiter := l.limiters[key]
	if limiter == nil {
		perMinute := rate.Every(time.Minute / time.Duration(l.requestsPerMinute))
		limiter = rate.NewLimiter(perMinute, l.requestsPerMinute)
		l.limiters[key] = limiter
	}
	l.mu.Unlock()
	return limiter.Allow()
}
