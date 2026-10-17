package audit

import (
	"bytes"
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

// Operation owns one frozen terminal record identity for an accepted request.
type Operation struct {
	mu         sync.Mutex
	logger     *Logger
	entry      Entry
	startedAt  time.Time
	finalized  bool
	prepared   *Entry
	completion *Completion
	attempted  bool
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
	entry.Principal = clonePrincipal(entry.Principal)
	entry.Policy = clonePolicyEvidence(entry.Policy)
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

// Finalize freezes one terminal record and retries only its audit persistence.
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

	if o.prepared == nil {
		entry := o.entry
		entry.Outcome = completion.Outcome
		entry.Direction = completion.Direction
		entry.Result = cloneRawMessage(completion.Result)
		entry.Error = cloneRPCError(completion.Error)
		entry.DurationMs = time.Since(o.startedAt).Milliseconds()
		if entry.DurationMs < 0 {
			entry.DurationMs = 0
		}
		prepared, err := o.logger.prepare(entry)
		if err != nil {
			return err
		}
		o.prepared = &prepared
		frozen := completion
		frozen.Result = cloneRawMessage(completion.Result)
		frozen.Error = cloneRPCError(completion.Error)
		o.completion = &frozen
	} else if !sameCompletion(*o.completion, completion) {
		return fmt.Errorf("audit: operation: completion changed after a failed append")
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = o.logger.recordPrepared(*o.prepared, o.attempted)
		o.attempted = true
		if err == nil {
			o.finalized = true
			return nil
		}
	}
	return err
}

func sameCompletion(a, b Completion) bool {
	if a.Outcome != b.Outcome || a.Direction != b.Direction || !bytes.Equal(a.Result, b.Result) {
		return false
	}
	if a.Error == nil || b.Error == nil {
		return a.Error == nil && b.Error == nil
	}
	return a.Error.Code == b.Error.Code && a.Error.Message == b.Error.Message && bytes.Equal(a.Error.Data, b.Error.Data)
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

func clonePrincipal(principal *Principal) *Principal {
	if principal == nil {
		return nil
	}
	cloned := *principal
	return &cloned
}

func clonePolicyEvidence(evidence *PolicyEvidence) *PolicyEvidence {
	if evidence == nil {
		return nil
	}
	cloned := *evidence
	return &cloned
}
