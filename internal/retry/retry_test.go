package retry

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestShouldRetryClassifiesTransientHTTPFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		err    error
		want   bool
	}{
		{name: "transport error", err: errors.New("connection refused"), want: true},
		{name: "request timeout", status: http.StatusRequestTimeout, want: true},
		{name: "too many requests", status: http.StatusTooManyRequests, want: true},
		{name: "bad gateway", status: http.StatusBadGateway, want: true},
		{name: "service unavailable", status: http.StatusServiceUnavailable, want: true},
		{name: "gateway timeout", status: http.StatusGatewayTimeout, want: true},
		{name: "internal server error", status: http.StatusInternalServerError, want: true},
		{name: "not implemented", status: http.StatusNotImplemented, want: false},
		{name: "bad request", status: http.StatusBadRequest, want: false},
		{name: "not found", status: http.StatusNotFound, want: false},
		{name: "success", status: http.StatusOK, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRetry(tc.status, tc.err); got != tc.want {
				t.Fatalf("ShouldRetry(%d, %v) = %v, want %v", tc.status, tc.err, got, tc.want)
			}
		})
	}
}

func TestStatusCodeClassifierRetriesOnlyConfiguredStatuses(t *testing.T) {
	classifier := StatusCodeClassifier(http.StatusTooManyRequests, http.StatusServiceUnavailable)
	cases := []struct {
		name   string
		status int
		err    error
		want   bool
	}{
		{name: "transport error", err: errors.New("connection reset"), want: true},
		{name: "too many requests", status: http.StatusTooManyRequests, want: true},
		{name: "service unavailable", status: http.StatusServiceUnavailable, want: true},
		{name: "bad gateway not configured", status: http.StatusBadGateway, want: false},
		{name: "request timeout not configured", status: http.StatusRequestTimeout, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifier(tc.status, tc.err); got != tc.want {
				t.Fatalf("classifier(%d, %v) = %v, want %v", tc.status, tc.err, got, tc.want)
			}
		})
	}
}

func TestPolicyCanRetryHonorsMaxRetriesAndClassifier(t *testing.T) {
	policy := Policy{
		MaxRetries: 2,
		ShouldRetry: StatusCodeClassifier(
			http.StatusTooManyRequests,
			http.StatusServiceUnavailable,
		),
	}

	if !policy.CanRetry(0, http.StatusServiceUnavailable, nil) {
		t.Fatal("attempt 0 should retry service unavailable")
	}
	if !policy.CanRetry(1, 0, errors.New("connection refused")) {
		t.Fatal("attempt 1 should retry transport error")
	}
	if policy.CanRetry(2, http.StatusServiceUnavailable, nil) {
		t.Fatal("attempt 2 should not retry when MaxRetries is 2")
	}
	if policy.CanRetry(0, http.StatusBadGateway, nil) {
		t.Fatal("bad gateway should not retry for status-limited policy")
	}
}

func TestPolicyDelayUsesBoundedExponentialBackoff(t *testing.T) {
	policy := Policy{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     time.Second,
		Multiplier:      2,
	}
	cases := []struct {
		name       string
		attempt    int
		retryAfter time.Duration
		want       time.Duration
	}{
		{name: "first attempt", attempt: 0, want: 100 * time.Millisecond},
		{name: "second attempt", attempt: 1, want: 200 * time.Millisecond},
		{name: "third attempt", attempt: 2, want: 400 * time.Millisecond},
		{name: "capped attempt", attempt: 4, want: time.Second},
		{name: "negative attempt", attempt: -1, want: 100 * time.Millisecond},
		{name: "retry after wins", attempt: 0, retryAfter: 500 * time.Millisecond, want: 500 * time.Millisecond},
		{name: "retry after capped", attempt: 0, retryAfter: 5 * time.Second, want: time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.Delay(tc.attempt, tc.retryAfter); got != tc.want {
				t.Fatalf("Delay(%d, %s) = %s, want %s", tc.attempt, tc.retryAfter, got, tc.want)
			}
		})
	}
}

func TestPolicyDelayDefaultsMultiplierAndClampsMaxBelowInitial(t *testing.T) {
	policy := Policy{
		InitialInterval: 200 * time.Millisecond,
		MaxInterval:     100 * time.Millisecond,
	}

	if got := policy.Delay(1, 0); got != 200*time.Millisecond {
		t.Fatalf("Delay with max below initial = %s, want 200ms", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "empty", value: "", want: 0},
		{name: "zero seconds", value: "0", want: 0},
		{name: "positive seconds", value: "5", want: 5 * time.Second},
		{name: "trimmed seconds", value: " 7 ", want: 7 * time.Second},
		{name: "negative seconds", value: "-1", want: 0},
		{name: "future http date", value: now.Add(2 * time.Minute).Format(http.TimeFormat), want: 2 * time.Minute},
		{name: "past http date", value: now.Add(-time.Minute).Format(http.TimeFormat), want: 0},
		{name: "invalid", value: "later", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfter(tc.value, now); got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = %s, want %s", tc.value, got, tc.want)
			}
		})
	}
}
