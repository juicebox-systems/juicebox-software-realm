package records

var memoryRecords = map[UserRecordId]UserRecord{}

type MemoryRecordStore struct{}

func (m MemoryRecordStore) GetRecord(recordId UserRecordId) (UserRecord, error) {
	record := memoryRecords[recordId]
	if record.RegistrationState == nil {
		record.RegistrationState = NotRegistered{}
	}
	return record, nil
}

func (m MemoryRecordStore) WriteRecord(recordId UserRecordId, record UserRecord) error {
	memoryRecords[recordId] = record
	return nil
}
