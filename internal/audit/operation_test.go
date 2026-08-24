package audit

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOutcomeValid(t *testing.T) {
	valid := []Outcome{
		OutcomeSuccess,
		OutcomeDenied,
		OutcomeRateLimited,
		OutcomeUpstreamError,
		OutcomeTimeout,
		OutcomeClientDisconnect,
		OutcomeMalformedUpstreamResponse,
		OutcomeCancelled,
		OutcomeInternalError,
	}
	for _, outcome := range valid {
		if !outcome.Valid() {
			t.Fatalf("outcome %q should be valid", outcome)
		}
	}
	if Outcome("pending").Valid() {
		t.Fatal("pending is not a terminal outcome")
	}
}

func TestOperationFinalizesExactlyOnce(t *testing.T) {
	store := newFakeStore()
	logger := NewLogger(LoggerConfig{Store: store, Transport: "http"})
	startedAt := time.Now().Add(-time.Second)
	operation, err := NewOperation(logger, Entry{
		Method:    "tools/call",
		RequestID: "42",
		ToolName:  "read_file",
		Params:    json.RawMessage(`{"path":"/tmp"}`),
	}, startedAt)
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	parsedID, err := uuid.Parse(operation.ID())
	if err != nil {
		t.Fatalf("operation ID is not a UUID: %v", err)
	}
	if parsedID.Version() != 7 {
		t.Fatalf("operation ID version = %d, want 7", parsedID.Version())
	}

	completion := Completion{
		Outcome:   OutcomeSuccess,
		Direction: DirectionServerToClient,
		Result:    json.RawMessage(`{"ok":true}`),
	}
	if err := operation.Finalize(completion); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := operation.Finalize(completion); !errors.Is(err, ErrOperationFinalized) {
		t.Fatalf("second finalize error = %v, want ErrOperationFinalized", err)
	}
	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
	entry := store.entries[0]
	if entry.AuditOperationID != operation.ID() {
		t.Fatalf("operation ID = %q, want %q", entry.AuditOperationID, operation.ID())
	}
	if entry.Outcome != OutcomeSuccess {
		t.Fatalf("outcome = %q, want success", entry.Outcome)
	}
	if entry.DurationMs < 0 {
		t.Fatalf("duration = %d, want non-negative", entry.DurationMs)
	}
}

func TestOperationConcurrentFinalizeStoresOneEntry(t *testing.T) {
	store := newFakeStore()
	operation, err := NewOperation(NewLogger(LoggerConfig{Store: store}), Entry{Method: "ping"}, time.Now())
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}

	const attempts = 16
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- operation.Finalize(Completion{Outcome: OutcomeSuccess})
		}()
	}
	wg.Wait()
	close(errs)

	var successes int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrOperationFinalized):
		default:
			t.Fatalf("unexpected finalize error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful finalizations = %d, want 1", successes)
	}
	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
}

func TestOperationRejectsInvalidOutcomeWithoutFinalizing(t *testing.T) {
	store := newFakeStore()
	operation, err := NewOperation(NewLogger(LoggerConfig{Store: store}), Entry{Method: "ping"}, time.Now())
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	if err := operation.Finalize(Completion{Outcome: "pending"}); !errors.Is(err, ErrInvalidOutcome) {
		t.Fatalf("invalid outcome error = %v, want ErrInvalidOutcome", err)
	}
	if err := operation.Finalize(Completion{Outcome: OutcomeSuccess}); err != nil {
		t.Fatalf("valid finalize after invalid attempt: %v", err)
	}
}

func TestOperationRetriesAfterStorageFailure(t *testing.T) {
	store := newFakeStore()
	store.appendOK = false
	store.failWith = errors.New("temporary storage failure")
	operation, err := NewOperation(NewLogger(LoggerConfig{Store: store}), Entry{Method: "ping"}, time.Now())
	if err != nil {
		t.Fatalf("new operation: %v", err)
	}
	completion := Completion{Outcome: OutcomeInternalError}
	if err := operation.Finalize(completion); err == nil {
		t.Fatal("expected first finalize to fail")
	}
	store.appendOK = true
	if err := operation.Finalize(completion); err != nil {
		t.Fatalf("retry finalize: %v", err)
	}
	if len(store.entries) != 1 {
		t.Fatalf("stored entries = %d, want 1", len(store.entries))
	}
}
