package records

import (
	"context"
	"errors"
	"sync"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

type MemoryRecordStore struct {
	lock    sync.Mutex
	records map[UserRecordID]UserRecord
}

func NewMemoryRecordStore() RecordStore {
	return &MemoryRecordStore{
		records: make(map[UserRecordID]UserRecord),
	}
}

func (m *MemoryRecordStore) GetRecord(ctx context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	_, span := otel.StartSpan(
		ctx,
		"GetRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemKey.String("memory")),
	)
	defer span.End()

	m.lock.Lock()
	defer m.lock.Unlock()

	record, ok := m.records[recordID]
	if !ok {
		return DefaultUserRecord(), nil, nil
	}
	return record, record, nil
}

func (m *MemoryRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	_, span := otel.StartSpan(
		ctx,
		"WriteRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemKey.String("memory")),
	)
	defer span.End()

	m.lock.Lock()
	defer m.lock.Unlock()

	existingRecord, exists := m.records[recordID]
	if !exists && readRecord == nil || existingRecord == readRecord {
		m.records[recordID] = record
		return nil
	}

	err := errors.New("record was unexpectedly mutated before write")
	return otel.RecordOutcome(err, span)
}
