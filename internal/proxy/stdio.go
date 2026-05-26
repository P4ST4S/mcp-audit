package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
	"github.com/P4ST4S/mcp-audit/internal/middleware"
	"github.com/P4ST4S/mcp-audit/internal/policy"
)

const (
	pendingCallTTL                  = 30 * time.Second
	pendingCallCleanupInterval      = 5 * time.Second
	upstreamGracefulShutdownTimeout = 5 * time.Second
	upstreamPipeDrainTimeout        = 1 * time.Second
)

// StdioConfig configures a stdio MCP proxy.
type StdioConfig struct {
	Upstream string
	Audit    *audit.Logger
	Limiter  *middleware.RateLimiter
	Policy   *policy.Engine
	Log      *slog.Logger
	ClientID string
	ServerID string
	Metrics  proxyMetrics
}

// StdioProxy transparently wraps a stdio MCP server process.
type StdioProxy struct {
	config StdioConfig
	log    *slog.Logger
	state  *rpcState
}

type proxyMetrics interface {
	RecordPolicyDecision(action string)
	RecordRateLimitRejection(clientID, toolName string)
}

// NewStdioProxy creates a stdio proxy.
func NewStdioProxy(config StdioConfig) *StdioProxy {
	logger := config.Log
	if logger == nil {
		logger = slog.Default()
	}
	return &StdioProxy{config: config, log: logger, state: newRPCState()}
}

// Run starts the upstream command and proxies stdin/stdout until shutdown.
func (p *StdioProxy) Run(ctx context.Context) error {
	if p.config.Upstream == "" {
		return fmt.Errorf("proxy: stdio: upstream is required")
	}
	cleanupCtx, stopCleanup := context.WithCancel(ctx)
	defer stopCleanup()
	go p.state.cleanupLoop(cleanupCtx, pendingCallTTL, pendingCallCleanupInterval)

	cmd := exec.Command("/bin/sh", "-c", p.config.Upstream)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("proxy: stdio: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("proxy: stdio: stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("proxy: stdio: start upstream: %w", err)
	}

	var stdoutMu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer stdin.Close()
		p.pipeClientToServer(ctx, os.Stdin, stdin, os.Stdout, &stdoutMu)
	}()
	go func() {
		defer wg.Done()
		p.pipeServerToClient(ctx, stdout, os.Stdout, &stdoutMu)
	}()

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- cmd.Wait()
	}()
	pipesDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(pipesDone)
	}()

	select {
	case <-ctx.Done():
		_ = p.shutdownUpstream(cmd, waitErr)
		p.waitForPipes(pipesDone)
		return nil
	case err := <-waitErr:
		p.waitForPipes(pipesDone)
		if err != nil {
			return fmt.Errorf("proxy: stdio: wait: %w", err)
		}
		return nil
	}
}

func (p *StdioProxy) shutdownUpstream(cmd *exec.Cmd, waitErr <-chan error) error {
	if cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		p.log.Warn("failed to interrupt upstream; killing", "error", err)
		_ = cmd.Process.Kill()
		return <-waitErr
	}

	timer := time.NewTimer(upstreamGracefulShutdownTimeout)
	defer timer.Stop()
	select {
	case err := <-waitErr:
		return err
	case <-timer.C:
		p.log.Warn("upstream did not exit after interrupt; killing", "timeout", upstreamGracefulShutdownTimeout)
		_ = cmd.Process.Kill()
		return <-waitErr
	}
}

func (p *StdioProxy) waitForPipes(pipesDone <-chan struct{}) {
	timer := time.NewTimer(upstreamPipeDrainTimeout)
	defer timer.Stop()
	select {
	case <-pipesDone:
	case <-timer.C:
		p.log.Debug("stdio pipe goroutines still draining")
	}
}

func (p *StdioProxy) pipeClientToServer(ctx context.Context, src io.Reader, upstream io.Writer, client io.Writer, clientMu *sync.Mutex) {
	scanner := newLineScanner(src)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		action := p.observeClientMessage(line)
		if action.reject != nil {
			clientMu.Lock()
			_, _ = client.Write(append(action.reject, '\n'))
			clientMu.Unlock()
			continue
		}
		if _, err := upstream.Write(append(line, '\n')); err != nil {
			p.log.Error("failed to write to upstream", "error", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	if err := scanner.Err(); err != nil {
		p.log.Error("failed to read client stdin", "error", err)
	}
}

func (p *StdioProxy) pipeServerToClient(ctx context.Context, src io.Reader, client io.Writer, clientMu *sync.Mutex) {
	scanner := newLineScanner(src)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		clientMu.Lock()
		_, err := client.Write(append(line, '\n'))
		clientMu.Unlock()
		if err != nil {
			p.log.Error("failed to write to client stdout", "error", err)
			return
		}
		p.observeServerMessage(line)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	if err := scanner.Err(); err != nil {
		p.log.Error("failed to read upstream stdout", "error", err)
	}
}

func newLineScanner(src io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return scanner
}

type messageAction struct {
	reject []byte
}

func (p *StdioProxy) observeClientMessage(raw []byte) messageAction {
	messages, err := decodeMessages(raw)
	if err != nil {
		p.log.Warn("failed to inspect client message", "error", err)
		return messageAction{}
	}
	for _, msg := range messages {
		if msg.Method != "" {
			toolName := toolNameFromParams(msg.Method, msg.Params)
			if msg.Method == "tools/call" {
				decision := p.evaluatePolicy(toolName)
				p.recordPolicyDecision(decision)
				if !decision.Allowed {
					rpcErr := policyError(decision)
					if err := p.record(pendingCall{
						method:    msg.Method,
						toolName:  toolName,
						params:    msg.Params,
						startedAt: time.Now(),
					}, audit.DirectionClientToServer, nil, rpcErr); err != nil {
						p.log.Error("failed to audit policy denied call", "error", err)
					}
					return messageAction{reject: buildErrorResponse(msg.ID, rpcErr)}
				}
			}
			if msg.Method == "tools/call" && !p.config.Limiter.Allow(p.config.ClientID, toolName) {
				if p.config.Metrics != nil {
					p.config.Metrics.RecordRateLimitRejection(p.config.ClientID, toolName)
				}
				rpcErr := &audit.RPCError{Code: -32029, Message: "rate limit exceeded"}
				if err := p.record(pendingCall{
					method:    msg.Method,
					toolName:  toolName,
					params:    msg.Params,
					startedAt: time.Now(),
				}, audit.DirectionClientToServer, nil, rpcErr); err != nil {
					p.log.Error("failed to audit rate limited call", "error", err)
				}
				return messageAction{reject: buildErrorResponse(msg.ID, rpcErr)}
			}
			if len(msg.ID) > 0 {
				p.state.rememberClient(string(msg.ID), pendingCall{
					method:    msg.Method,
					toolName:  toolName,
					params:    msg.Params,
					startedAt: time.Now(),
				})
				continue
			}
			if err := p.record(pendingCall{method: msg.Method, toolName: toolName, params: msg.Params, startedAt: time.Now()}, audit.DirectionClientToServer, nil, nil); err != nil {
				p.log.Error("failed to audit client notification", "error", err)
			}
			continue
		}
		if len(msg.ID) > 0 {
			if call, ok := p.state.takeServer(string(msg.ID)); ok {
				if err := p.record(call, audit.DirectionClientToServer, msg.Result, msg.Error); err != nil {
					p.log.Error("failed to audit client response", "error", err)
				}
			}
		}
	}
	return messageAction{}
}

func (p *StdioProxy) observeServerMessage(raw []byte) {
	messages, err := decodeMessages(raw)
	if err != nil {
		p.log.Warn("failed to inspect server message", "error", err)
		return
	}
	for _, msg := range messages {
		if msg.Method != "" {
			toolName := toolNameFromParams(msg.Method, msg.Params)
			if len(msg.ID) > 0 {
				p.state.rememberServer(string(msg.ID), pendingCall{
					method:    msg.Method,
					toolName:  toolName,
					params:    msg.Params,
					startedAt: time.Now(),
				})
				continue
			}
			if err := p.record(pendingCall{method: msg.Method, toolName: toolName, params: msg.Params, startedAt: time.Now()}, audit.DirectionServerToClient, nil, nil); err != nil {
				p.log.Error("failed to audit server notification", "error", err)
			}
			continue
		}
		if len(msg.ID) > 0 {
			if call, ok := p.state.takeClient(string(msg.ID)); ok {
				if err := p.record(call, audit.DirectionServerToClient, msg.Result, msg.Error); err != nil {
					p.log.Error("failed to audit server response", "error", err)
				}
			}
		}
	}
}

func (p *StdioProxy) record(call pendingCall, direction string, result json.RawMessage, rpcErr *audit.RPCError) error {
	return p.config.Audit.Record(audit.Entry{
		Direction:  direction,
		Method:     call.method,
		ToolName:   call.toolName,
		Params:     call.params,
		Result:     result,
		Error:      rpcErr,
		DurationMs: time.Since(call.startedAt).Milliseconds(),
		ClientID:   p.config.ClientID,
		ServerID:   p.config.ServerID,
	})
}

func (p *StdioProxy) evaluatePolicy(toolName string) policy.Decision {
	if p.config.Policy == nil {
		return policy.Decision{Allowed: true, Action: policy.ActionAllow, RuleIndex: -1}
	}
	return p.config.Policy.Evaluate(policy.Request{
		ClientID: p.config.ClientID,
		ServerID: p.config.ServerID,
		ToolName: toolName,
	})
}

func (p *StdioProxy) recordPolicyDecision(decision policy.Decision) {
	if p.config.Policy == nil || p.config.Metrics == nil {
		return
	}
	p.config.Metrics.RecordPolicyDecision(decision.Action)
}

type pendingCall struct {
	method    string
	toolName  string
	params    json.RawMessage
	startedAt time.Time
}

type rpcState struct {
	mu            sync.Mutex
	clientPending map[string]pendingCall
	serverPending map[string]pendingCall
}

func newRPCState() *rpcState {
	return &rpcState{
		clientPending: make(map[string]pendingCall),
		serverPending: make(map[string]pendingCall),
	}
}

func (s *rpcState) cleanupLoop(ctx context.Context, ttl time.Duration, interval time.Duration) {
	if ttl <= 0 {
		return
	}
	if interval <= 0 {
		interval = ttl
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.purgeExpired(now, ttl)
		}
	}
}

func (s *rpcState) purgeExpired(now time.Time, ttl time.Duration) int {
	cutoff := now.Add(-ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	purged := 0
	for id, call := range s.clientPending {
		if call.startedAt.Before(cutoff) {
			delete(s.clientPending, id)
			purged++
		}
	}
	for id, call := range s.serverPending {
		if call.startedAt.Before(cutoff) {
			delete(s.serverPending, id)
			purged++
		}
	}
	return purged
}

func (s *rpcState) rememberClient(id string, call pendingCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientPending[id] = call
}

func (s *rpcState) rememberServer(id string, call pendingCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverPending[id] = call
}

func (s *rpcState) takeClient(id string) (pendingCall, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call, ok := s.clientPending[id]
	delete(s.clientPending, id)
	return call, ok
}

func (s *rpcState) takeServer(id string) (pendingCall, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call, ok := s.serverPending[id]
	delete(s.serverPending, id)
	return call, ok
}

type rpcMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *audit.RPCError `json:"error,omitempty"`
}

func decodeMessages(raw []byte) ([]rpcMessage, error) {
	var single rpcMessage
	if err := json.Unmarshal(raw, &single); err == nil && (single.Method != "" || len(single.ID) > 0) {
		return []rpcMessage{single}, nil
	}
	var batch []rpcMessage
	if err := json.Unmarshal(raw, &batch); err != nil {
		return nil, fmt.Errorf("proxy: jsonrpc: decode: %w", err)
	}
	return batch, nil
}

func toolNameFromParams(method string, params json.RawMessage) string {
	if method != "tools/call" || len(params) == 0 {
		return ""
	}
	var named struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &named); err == nil && named.Name != "" {
		return named.Name
	}
	var alternate struct {
		ToolName string `json:"tool_name"`
	}
	if err := json.Unmarshal(params, &alternate); err == nil {
		return alternate.ToolName
	}
	return ""
}

func buildErrorResponse(id json.RawMessage, rpcErr *audit.RPCError) []byte {
	response := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *audit.RPCError `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Error:   rpcErr,
	}
	out, err := json.Marshal(response)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32029,"message":"rate limit exceeded"}}`)
	}
	return out
}
