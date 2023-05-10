package records

import (
	"context"
	"errors"
)

var memoryRecords = map[UserRecordID]UserRecord{}

type MemoryRecordStore struct{}

func (m MemoryRecordStore) GetRecord(_ context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	record, ok := memoryRecords[recordID]
	if !ok {
		return DefaultUserRecord(), nil, nil
	}
	return record, record, nil
}

func (m MemoryRecordStore) WriteRecord(_ context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	existingRecord, exists := memoryRecords[recordID]
	if !exists && readRecord == nil || existingRecord == readRecord {
		memoryRecords[recordID] = record
		return nil
	}
	return errors.New("record was unexpectedly mutated before write")
}
