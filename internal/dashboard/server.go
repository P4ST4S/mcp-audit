package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

const (
	// DefaultBindAddress keeps the dashboard reachable from localhost only by default.
	DefaultBindAddress        = "127.0.0.1"
	bearerChallenge           = `Bearer realm="mcp-audit-dashboard"`
	bearerAuthorizationScheme = "Bearer"
	authFailureLimit          = 10
	authFailureWindow         = time.Minute
	authFailureMaxPrincipals  = 4096
)

// Config configures the audit dashboard.
type Config struct {
	Enabled     bool
	BindAddress string
	Port        int
	Auth        AuthConfig
	Store       audit.Store
	Log         *slog.Logger
}

// AuthConfig configures dashboard HTTP authentication.
type AuthConfig struct {
	Token string
}

// Server serves the read-only audit dashboard.
type Server struct {
	config       Config
	server       *http.Server
	log          *slog.Logger
	authFailures *authFailureLimiter
}

// NewServer creates a dashboard server.
func NewServer(config Config) *Server {
	logger := config.Log
	if logger == nil {
		logger = slog.Default()
	}
	if strings.TrimSpace(config.BindAddress) == "" {
		config.BindAddress = DefaultBindAddress
	}
	config.Auth.Token = strings.TrimSpace(config.Auth.Token)
	mux := http.NewServeMux()
	s := &Server{config: config, log: logger}
	if config.Auth.Token != "" {
		s.authFailures = newAuthFailureLimiter(authFailureLimit, authFailureWindow, authFailureMaxPrincipals)
	}
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/entries", s.entries)
	mux.HandleFunc("/api/stats", s.stats)
	s.server = &http.Server{
		Addr:              s.listenAddress(),
		Handler:           s.authenticate(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

func (s *Server) listenAddress() string {
	return net.JoinHostPort(s.config.BindAddress, strconv.Itoa(s.config.Port))
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	if s.config.Auth.Token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := authPrincipal(r)
		if validBearerToken(r.Header.Get("Authorization"), s.config.Auth.Token) {
			s.authFailures.reset(principal)
			next.ServeHTTP(w, r)
			return
		}
		if !s.authFailures.recordFailure(principal, time.Now()) {
			w.Header().Set("Retry-After", strconv.Itoa(int(authFailureWindow/time.Second)))
			http.Error(w, "too many authentication attempts", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("WWW-Authenticate", bearerChallenge)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// validBearerToken returns true iff the Authorization header presents the
// configured bearer token. Constant-time comparison is used for the token body
// itself; the length-mismatch fast path is intentional and leaks only the
// configured token's length, which is conventionally not secret.
func validBearerToken(header string, want string) bool {
	scheme, credentials, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, bearerAuthorizationScheme) {
		return false
	}
	got := strings.TrimLeftFunc(credentials, unicode.IsSpace)
	if got == "" || len(got) != len(want) || strings.ContainsFunc(got, unicode.IsSpace) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func authPrincipal(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

type authFailureLimiter struct {
	mu            sync.Mutex
	limit         int
	window        time.Duration
	maxPrincipals int
	attempts      map[string]authFailureBucket
}

type authFailureBucket struct {
	windowStart time.Time
	failures    int
}

func newAuthFailureLimiter(limit int, window time.Duration, maxPrincipals int) *authFailureLimiter {
	return &authFailureLimiter{
		limit:         limit,
		window:        window,
		maxPrincipals: maxPrincipals,
		attempts:      make(map[string]authFailureBucket),
	}
}

func (l *authFailureLimiter) recordFailure(principal string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.attempts[principal]
	if !ok {
		l.ensureCapacity(now)
		bucket = authFailureBucket{windowStart: now}
	}
	if now.Sub(bucket.windowStart) >= l.window {
		bucket = authFailureBucket{windowStart: now}
	}
	bucket.failures++
	l.attempts[principal] = bucket
	return bucket.failures <= l.limit
}

func (l *authFailureLimiter) reset(principal string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, principal)
}

func (l *authFailureLimiter) ensureCapacity(now time.Time) {
	if len(l.attempts) < l.maxPrincipals {
		return
	}
	var oldestPrincipal string
	var oldestTime time.Time
	for principal, bucket := range l.attempts {
		if now.Sub(bucket.windowStart) >= l.window {
			delete(l.attempts, principal)
			continue
		}
		if oldestPrincipal == "" || bucket.windowStart.Before(oldestTime) {
			oldestPrincipal = principal
			oldestTime = bucket.windowStart
		}
	}
	if len(l.attempts) >= l.maxPrincipals && oldestPrincipal != "" {
		delete(l.attempts, oldestPrincipal)
	}
}

// ListenAndServe starts the dashboard and shuts down when ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if !s.config.Enabled {
		return nil
	}
	errs := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errs <- err
			return
		}
		errs <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("dashboard: shutdown: %w", err)
		}
		return <-errs
	case err := <-errs:
		if err != nil {
			return fmt.Errorf("dashboard: listen: %w", err)
		}
		return nil
	}
}

func (s *Server) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, nil); err != nil {
		s.log.Error("failed to render dashboard", "error", err)
	}
}

func (s *Server) entries(w http.ResponseWriter, r *http.Request) {
	filter, err := queryFilter(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries, err := s.config.Store.Query(filter)
	if err != nil {
		http.Error(w, "failed to query entries", http.StatusInternalServerError)
		s.log.Error("failed to query entries", "error", err)
		return
	}
	writeJSON(w, entries)
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	stats, err := s.config.Store.Stats()
	if err != nil {
		http.Error(w, "failed to query stats", http.StatusInternalServerError)
		s.log.Error("failed to query stats", "error", err)
		return
	}
	writeJSON(w, stats)
}

func queryFilter(r *http.Request) (audit.QueryFilter, error) {
	values := r.URL.Query()
	limit := 100
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return audit.QueryFilter{}, fmt.Errorf("dashboard: invalid limit")
		}
		limit = parsed
	}
	filter := audit.QueryFilter{
		Method:   values.Get("method"),
		ToolName: values.Get("tool_name"),
		ClientID: values.Get("client_id"),
		Limit:    limit,
	}
	if raw := values.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return audit.QueryFilter{}, fmt.Errorf("dashboard: invalid from timestamp")
		}
		filter.From = parsed
	}
	if raw := values.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return audit.QueryFilter{}, fmt.Errorf("dashboard: invalid to timestamp")
		}
		filter.To = parsed
	}
	return filter, nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

var pageTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-audit</title>
<style>
:root { color-scheme: dark; --bg: #111418; --panel: #171c22; --line: #2a323c; --text: #e9eef5; --muted: #9aa7b5; --accent: #68c1ff; --bad: #ff7777; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
header { padding: 18px 24px 12px; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 16px; }
h1 { margin: 0; font-size: 20px; letter-spacing: 0; }
main { padding: 18px 24px 28px; }
.stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
.stat, .filters { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 12px; }
.stat .value { font-size: 24px; margin-top: 4px; }
.label { color: var(--muted); font-size: 12px; text-transform: uppercase; }
.filters { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; margin-bottom: 16px; }
input, button { width: 100%; border: 1px solid var(--line); background: #0d1014; color: var(--text); border-radius: 5px; padding: 8px 9px; font: inherit; }
button { cursor: pointer; background: #1d2731; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
th, td { border-bottom: 1px solid var(--line); padding: 9px 8px; text-align: left; vertical-align: top; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
th { color: var(--muted); font-size: 12px; font-weight: 600; }
tr[data-entry] { cursor: pointer; }
tr[data-entry]:hover { background: #151b22; }
.method { color: var(--accent); }
.error { color: var(--bad); }
pre { margin: 0; white-space: pre-wrap; word-break: break-word; background: #0d1014; border: 1px solid var(--line); border-radius: 6px; padding: 10px; max-height: 360px; overflow: auto; }
.details { display: none; }
.details.open { display: table-row; }
.details td { white-space: normal; }
.payloads { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 900px) { .stats, .filters, .payloads { grid-template-columns: 1fr; } th:nth-child(1), td:nth-child(1), th:nth-child(6), td:nth-child(6) { display: none; } main, header { padding-left: 12px; padding-right: 12px; } }
</style>
</head>
<body>
<header><h1>mcp-audit</h1><div id="refresh" class="label">refreshing</div></header>
<main>
<section class="stats">
<div class="stat"><div class="label">Calls today</div><div id="totalToday" class="value">0</div></div>
<div class="stat"><div class="label">Error rate</div><div id="errorRate" class="value">0%</div></div>
<div class="stat"><div class="label">Top tools</div><div id="topTools" class="value">-</div></div>
</section>
<section class="filters">
<input id="method" placeholder="method">
<input id="tool_name" placeholder="tool_name">
<input id="client_id" placeholder="client_id">
<input id="from" placeholder="from RFC3339">
<input id="to" placeholder="to RFC3339">
<button id="apply">Apply</button>
</section>
<table>
<thead><tr><th>Time</th><th>Direction</th><th>Method</th><th>Tool</th><th>Client</th><th>Duration</th><th>Status</th></tr></thead>
<tbody id="entries"></tbody>
</table>
</main>
<script>
const tbody = document.querySelector("#entries");
const fields = ["method", "tool_name", "client_id", "from", "to"];
document.querySelector("#apply").addEventListener("click", refresh);
function params() {
  const q = new URLSearchParams({limit: "100"});
  fields.forEach(id => { const v = document.getElementById(id).value.trim(); if (v) q.set(id, v); });
  return q.toString();
}
function pretty(v) { return v ? JSON.stringify(v, null, 2) : ""; }
async function refresh() {
  const [entries, stats] = await Promise.all([
    fetch("/api/entries?" + params()).then(r => r.json()),
    fetch("/api/stats").then(r => r.json())
  ]);
  document.querySelector("#totalToday").textContent = stats.total_today || 0;
  document.querySelector("#errorRate").textContent = ((stats.error_rate || 0) * 100).toFixed(1) + "%";
  document.querySelector("#topTools").textContent = (stats.top_tools || []).map(t => t.name + " " + t.count).join(", ") || "-";
  tbody.textContent = "";
  entries.forEach(e => {
    const row = document.createElement("tr");
    row.dataset.entry = e.id;
    row.innerHTML = "<td>" + new Date(e.timestamp).toLocaleString() + "</td><td>" + e.direction + "</td><td class='method'>" + e.method + "</td><td>" + (e.tool_name || "") + "</td><td>" + e.client_id + "</td><td>" + e.duration_ms + " ms</td><td class='" + (e.error ? "error" : "") + "'>" + (e.error ? "error" : "ok") + "</td>";
    const details = document.createElement("tr");
    details.className = "details";
    details.innerHTML = "<td colspan='7'><div class='payloads'><pre>" + escapeHTML(pretty(e.params)) + "</pre><pre>" + escapeHTML(pretty(e.result || e.error)) + "</pre></div></td>";
    row.addEventListener("click", () => details.classList.toggle("open"));
    tbody.appendChild(row);
    tbody.appendChild(details);
  });
  document.querySelector("#refresh").textContent = "updated " + new Date().toLocaleTimeString();
}
function escapeHTML(s) { return s.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[c])); }
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`))
