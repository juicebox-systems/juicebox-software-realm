package records

import "errors"

var memoryRecords = map[UserRecordID]UserRecord{}

type MemoryRecordStore struct{}

func (m MemoryRecordStore) GetRecord(recordID UserRecordID) (UserRecord, interface{}, error) {
	record, ok := memoryRecords[recordID]
	if !ok {
		return DefaultUserRecord(), nil, nil
	}
	return record, record, nil
}

func (m MemoryRecordStore) WriteRecord(recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	existingRecord, isNil := memoryRecords[recordID]
	if isNil && readRecord == nil || existingRecord == readRecord {
		memoryRecords[recordID] = record
		return nil
	}
	return errors.New("record was unexpectedly mutated before write")
}
