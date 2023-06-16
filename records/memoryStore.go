package records

import (
	"context"
	"errors"

	"github.com/juicebox-software-realm/otel"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

var memoryRecords = map[UserRecordID]UserRecord{}

type MemoryRecordStore struct{}

func (m MemoryRecordStore) GetRecord(ctx context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	_, span := otel.StartSpan(
		ctx,
		"GetRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemKey.String("memory")),
	)
	defer span.End()

	record, ok := memoryRecords[recordID]
	if !ok {
		return DefaultUserRecord(), nil, nil
	}
	return record, record, nil
}

func (m MemoryRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	_, span := otel.StartSpan(
		ctx,
		"WriteRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemKey.String("memory")),
	)
	defer span.End()

	existingRecord, exists := memoryRecords[recordID]
	if !exists && readRecord == nil || existingRecord == readRecord {
		memoryRecords[recordID] = record
		return nil
	}

	err := errors.New("record was unexpectedly mutated before write")
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return err
}
