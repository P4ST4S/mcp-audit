package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrOperationFinalized is returned when a second terminal event is attempted.
	ErrOperationFinalized = errors.New("audit: operation already finalized")
	// ErrInvalidOutcome is returned for a non-terminal or unknown outcome.
	ErrInvalidOutcome = errors.New("audit: invalid terminal outcome")
)

// Completion contains the response-side data used to finalize an operation.
type Completion struct {
	Outcome   Outcome
	Direction string
	Result    json.RawMessage
	Error     *RPCError
}

// Operation owns the exactly-once terminal audit event for one accepted request.
type Operation struct {
	mu        sync.Mutex
	logger    *Logger
	entry     Entry
	startedAt time.Time
	finalized bool
}

// NewOperation starts an operation and assigns it a UUIDv7 correlation ID.
func NewOperation(logger *Logger, entry Entry, startedAt time.Time) (*Operation, error) {
	if logger == nil {
		return nil, fmt.Errorf("audit: operation: logger is required")
	}
	operationID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("audit: operation: generate UUIDv7: %w", err)
	}
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	entry.AuditOperationID = operationID.String()
	entry.Params = cloneRawMessage(entry.Params)
	entry.Result = nil
	entry.Error = nil
	entry.Outcome = ""
	return &Operation{
		logger:    logger,
		entry:     entry,
		startedAt: startedAt,
	}, nil
}

// ID returns the stable correlation ID assigned when the operation was accepted.
func (o *Operation) ID() string {
	if o == nil {
		return ""
	}
	return o.entry.AuditOperationID
}

// Finalize records the operation's terminal event exactly once.
func (o *Operation) Finalize(completion Completion) error {
	if o == nil {
		return fmt.Errorf("audit: operation: nil operation")
	}
	if !completion.Outcome.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidOutcome, completion.Outcome)
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finalized {
		return ErrOperationFinalized
	}

	entry := o.entry
	entry.Outcome = completion.Outcome
	entry.Direction = completion.Direction
	entry.Result = cloneRawMessage(completion.Result)
	entry.Error = cloneRPCError(completion.Error)
	entry.DurationMs = time.Since(o.startedAt).Milliseconds()
	if entry.DurationMs < 0 {
		entry.DurationMs = 0
	}
	if err := o.logger.Record(entry); err != nil {
		return err
	}
	o.finalized = true
	return nil
}

func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), raw...)
}

func cloneRPCError(rpcErr *RPCError) *RPCError {
	if rpcErr == nil {
		return nil
	}
	cloned := *rpcErr
	cloned.Data = cloneRawMessage(rpcErr.Data)
	return &cloned
}
