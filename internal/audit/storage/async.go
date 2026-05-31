package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/P4ST4S/mcp-audit/internal/audit"
)

const (
	defaultAsyncQueueSize       = 4096
	defaultAsyncBatchSize       = 128
	defaultAsyncFlushIntervalMS = 1000
)

// AsyncConfig configures asynchronous audit storage.
type AsyncConfig struct {
	QueueSize       int
	BatchSize       int
	FlushIntervalMS int
}

type batchAppender interface {
	AppendBatch(entries []audit.Entry) error
}

// AsyncMetricsRecorder records async queue metrics.
type AsyncMetricsRecorder interface {
	SetAsyncQueueDepth(depth int)
	SetAsyncQueueCapacity(capacity int)
	RecordAsyncBackpressure()
	RecordAsyncBatch(size int)
}

// AsyncStore wraps a Store with a bounded channel-backed ring buffer and batched flushes.
type AsyncStore struct {
	store         audit.Store
	metrics       AsyncMetricsRecorder
	entries       chan audit.Entry
	flushRequests chan chan error
	done          chan struct{}
	closeOnce     sync.Once
	closeMu       sync.RWMutex

	batchSize     int
	flushInterval time.Duration

	errMu sync.Mutex
	err   error
}

// NewAsyncStore creates an asynchronous Store wrapper.
func NewAsyncStore(store audit.Store, config AsyncConfig) *AsyncStore {
	return NewAsyncStoreWithMetrics(store, config, nil)
}

// NewAsyncStoreWithMetrics creates an asynchronous Store wrapper with metrics.
func NewAsyncStoreWithMetrics(store audit.Store, config AsyncConfig, metrics AsyncMetricsRecorder) *AsyncStore {
	if config.QueueSize <= 0 {
		config.QueueSize = defaultAsyncQueueSize
	}
	if config.BatchSize <= 0 {
		config.BatchSize = defaultAsyncBatchSize
	}
	if config.FlushIntervalMS <= 0 {
		config.FlushIntervalMS = defaultAsyncFlushIntervalMS
	}
	async := &AsyncStore{
		store:         store,
		metrics:       metrics,
		entries:       make(chan audit.Entry, config.QueueSize),
		flushRequests: make(chan chan error),
		done:          make(chan struct{}),
		batchSize:     config.BatchSize,
		flushInterval: time.Duration(config.FlushIntervalMS) * time.Millisecond,
	}
	async.updateQueueMetrics()
	if async.metrics != nil {
		async.metrics.SetAsyncQueueCapacity(cap(async.entries))
	}
	go async.run()
	return async
}

// Append queues entry for asynchronous storage. It blocks when the queue is full.
func (s *AsyncStore) Append(entry audit.Entry) error {
	if err := s.currentErr(); err != nil {
		return err
	}
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	// Check done under the read lock so we never send on a closed channel.
	select {
	case <-s.done:
		if err := s.currentErr(); err != nil {
			return err
		}
		return fmt.Errorf("audit: async: append after close")
	default:
	}
	select {
	case s.entries <- entry:
		s.updateQueueMetrics()
		return nil
	default:
		if s.metrics != nil {
			s.metrics.RecordAsyncBackpressure()
		}
		select {
		case s.entries <- entry:
			s.updateQueueMetrics()
			return nil
		case <-s.done:
			if err := s.currentErr(); err != nil {
				return err
			}
			return fmt.Errorf("audit: async: append after close")
		}
	}
}

// Flush persists all entries queued before the flush completes.
func (s *AsyncStore) Flush() error {
	reply := make(chan error, 1)
	select {
	case s.flushRequests <- reply:
		return <-reply
	case <-s.done:
		return s.currentErr()
	}
}

// Query flushes pending writes and delegates to the wrapped store.
func (s *AsyncStore) Query(filter audit.QueryFilter) ([]audit.Entry, error) {
	if err := s.Flush(); err != nil {
		return nil, err
	}
	return s.store.Query(filter)
}

// Stats flushes pending writes and delegates to the wrapped store.
func (s *AsyncStore) Stats() (audit.Stats, error) {
	if err := s.Flush(); err != nil {
		return audit.Stats{}, err
	}
	return s.store.Stats()
}

// Close flushes queued entries, stops the worker, and closes the wrapped store.
func (s *AsyncStore) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.closeMu.Lock()
		close(s.entries)
		s.closeMu.Unlock()
		<-s.done
		err = s.currentErr()
		if closeErr := s.store.Close(); err == nil {
			err = closeErr
		}
	})
	return err
}

func (s *AsyncStore) run() {
	defer close(s.done)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]audit.Entry, 0, s.batchSize)
	for {
		select {
		case entry, ok := <-s.entries:
			s.updateQueueMetrics()
			if !ok {
				s.setErr(s.writeBatch(&batch))
				return
			}
			batch = append(batch, entry)
			if len(batch) >= s.batchSize {
				if err := s.writeBatch(&batch); err != nil {
					s.setErr(err)
					return
				}
			}
		case reply := <-s.flushRequests:
			err := s.drainAndFlush(&batch)
			reply <- err
			if err != nil {
				s.setErr(err)
				return
			}
		case <-ticker.C:
			if err := s.writeBatch(&batch); err != nil {
				s.setErr(err)
				return
			}
		}
	}
}

func (s *AsyncStore) drainAndFlush(batch *[]audit.Entry) error {
	for {
		select {
		case entry, ok := <-s.entries:
			s.updateQueueMetrics()
			if !ok {
				return s.writeBatch(batch)
			}
			*batch = append(*batch, entry)
			if len(*batch) >= s.batchSize {
				if err := s.writeBatch(batch); err != nil {
					return err
				}
			}
		default:
			return s.writeBatch(batch)
		}
	}
}

func (s *AsyncStore) writeBatch(batch *[]audit.Entry) error {
	if len(*batch) == 0 {
		return nil
	}
	if store, ok := s.store.(batchAppender); ok {
		if err := store.AppendBatch(*batch); err != nil {
			return fmt.Errorf("audit: async: append batch: %w", err)
		}
	} else {
		for _, entry := range *batch {
			if err := s.store.Append(entry); err != nil {
				return fmt.Errorf("audit: async: append: %w", err)
			}
		}
	}
	if s.metrics != nil {
		s.metrics.RecordAsyncBatch(len(*batch))
	}
	*batch = (*batch)[:0]
	s.updateQueueMetrics()
	return nil
}

func (s *AsyncStore) currentErr() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

func (s *AsyncStore) setErr(err error) {
	if err == nil {
		return
	}
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

func (s *AsyncStore) updateQueueMetrics() {
	if s.metrics == nil {
		return
	}
	s.metrics.SetAsyncQueueDepth(len(s.entries))
}
