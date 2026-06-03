package retry

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Classifier decides whether an HTTP response status or request error is retryable.
type Classifier func(status int, err error) bool

// Policy configures bounded exponential backoff for HTTP retries.
type Policy struct {
	MaxRetries      int
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	Classifier      Classifier
}

// CanRetry reports whether attempt can be retried under the policy.
func (p Policy) CanRetry(attempt int, status int, err error) bool {
	if p.MaxRetries <= 0 || attempt >= p.MaxRetries {
		return false
	}
	return p.ShouldRetry(status, err)
}

// ShouldRetry reports whether a status or error is retryable under the policy classifier.
func (p Policy) ShouldRetry(status int, err error) bool {
	classifier := p.Classifier
	if classifier == nil {
		classifier = ShouldRetry
	}
	return classifier(status, err)
}

// Delay returns the wait before the next retry attempt.
func (p Policy) Delay(attempt int, retryAfter time.Duration) time.Duration {
	maxInterval := p.MaxInterval
	if p.InitialInterval > 0 && (maxInterval <= 0 || maxInterval < p.InitialInterval) {
		maxInterval = p.InitialInterval
	}
	if retryAfter > 0 {
		return capDelay(retryAfter, maxInterval)
	}
	if p.InitialInterval <= 0 {
		return 0
	}
	if attempt < 0 {
		attempt = 0
	}
	multiplier := p.Multiplier
	if multiplier <= 1 {
		multiplier = 2
	}
	delay := float64(p.InitialInterval)
	if attempt > 0 {
		delay *= math.Pow(multiplier, float64(attempt))
	}
	if delay > float64(math.MaxInt64) {
		return capDelay(time.Duration(math.MaxInt64), maxInterval)
	}
	return capDelay(time.Duration(delay), maxInterval)
}

// ShouldRetry classifies retryable HTTP transport errors and transient statuses.
func ShouldRetry(status int, err error) bool {
	if err != nil {
		return true
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return true
	}
	return status >= http.StatusInternalServerError && status != http.StatusNotImplemented
}

// StatusCodeClassifier returns a classifier that retries request errors and selected statuses.
func StatusCodeClassifier(statuses ...int) Classifier {
	retryable := make(map[int]struct{}, len(statuses))
	for _, status := range statuses {
		retryable[status] = struct{}{}
	}
	return func(status int, err error) bool {
		if err != nil {
			return true
		}
		_, ok := retryable[status]
		return ok
	}
}

// ParseRetryAfter parses a Retry-After header value.
func ParseRetryAfter(value string) time.Duration {
	return parseRetryAfter(value, time.Now())
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := when.Sub(now)
		if delay > 0 {
			return delay
		}
	}
	return 0
}

func capDelay(delay, maxDelay time.Duration) time.Duration {
	if maxDelay > 0 && delay > maxDelay {
		return maxDelay
	}
	return delay
}
