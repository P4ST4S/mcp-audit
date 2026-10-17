package audit

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type ambiguousStore struct {
	fakeStore
	writes int
}

type retryStore struct {
	fakeStore
	attempts []Entry
	fail     bool
}

func (s *retryStore) Append(entry Entry) error {
	s.attempts = append(s.attempts, entry)
	if s.fail {
		return errors.New("storage unavailable")
	}
	return s.fakeStore.Append(entry)
}

func TestFinalizeFreezesSignedRecordAcrossFailedAttempts(t *testing.T) {
	store := &retryStore{fakeStore: fakeStore{appendOK: true}, fail: true}
	logger := NewLogger(LoggerConfig{Store: store, Signer: NewSigner("retry signing secret")})
	op, err := NewOperation(logger, Entry{Method: "tools/call"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	completion := Completion{Outcome: OutcomeSuccess, Result: json.RawMessage(`{"ok":true}`)}
	if err := op.Finalize(completion); err == nil {
		t.Fatal("failed storage acknowledged")
	}
	if len(store.attempts) != 3 {
		t.Fatalf("attempts=%d", len(store.attempts))
	}
	changed := completion
	changed.Result = json.RawMessage(`{"ok":false}`)
	if err := op.Finalize(changed); err == nil {
		t.Fatal("changed completion accepted")
	}
	store.fail = false
	if err := op.Finalize(completion); err != nil {
		t.Fatal(err)
	}
	if len(store.entries) != 1 {
		t.Fatalf("entries=%d", len(store.entries))
	}
	for _, entry := range store.attempts {
		if !EqualEntries(entry, store.entries[0]) {
			t.Fatal("record identity or signature changed during retry")
		}
	}
	if len(store.entries) != 1 {
		t.Fatalf("entries=%d", len(store.entries))
	}
}

type conflictStore struct{ ambiguousStore }

func (s *conflictStore) LookupEntry(id string) (Entry, bool, error) {
	entry, found, err := s.ambiguousStore.LookupEntry(id)
	entry.Method = "other"
	return entry, found, err
}
func TestFinalizeRejectsConflictingStoredIdentity(t *testing.T) {
	store := &conflictStore{}
	op, err := NewOperation(NewLogger(LoggerConfig{Store: store}), Entry{Method: "ping"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Finalize(Completion{Outcome: OutcomeSuccess}); err == nil {
		t.Fatal("conflicting record treated as acknowledged")
	}
	if store.writes != 1 {
		t.Fatal("blind duplicate append after identity conflict")
	}
}

func TestRecordComparisonNormalizesTimestampWithoutIgnoringContent(t *testing.T) {
	a := Entry{ID: "same", Timestamp: time.Date(2026, 10, 17, 12, 0, 0, 123, time.UTC), Method: "ping"}
	b := a
	b.Timestamp = a.Timestamp.In(time.FixedZone("offset", 2*60*60))
	if !EqualEntries(a, b) {
		t.Fatal("equivalent stored timestamp rejected")
	}
	b.Method = "changed"
	if EqualEntries(a, b) {
		t.Fatal("changed content accepted")
	}
}

func (s *ambiguousStore) Append(entry Entry) error {
	s.entries = append(s.entries, entry)
	s.writes++
	if s.writes == 1 {
		return errors.New("injected error after write")
	}
	return nil
}
func (s *ambiguousStore) LookupEntry(id string) (Entry, bool, error) {
	for _, entry := range s.entries {
		if entry.ID == id {
			return entry, true, nil
		}
	}
	return Entry{}, false, nil
}

func TestFinalizeResolvesAmbiguousWriteWithoutDuplicate(t *testing.T) {
	store := &ambiguousStore{}
	op, err := NewOperation(NewLogger(LoggerConfig{Store: store}), Entry{Method: "ping"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Finalize(Completion{Outcome: OutcomeSuccess}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if store.writes != 1 || len(store.entries) != 1 {
		t.Fatalf("writes=%d entries=%d", store.writes, len(store.entries))
	}
}
