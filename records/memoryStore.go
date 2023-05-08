package records

var memoryRecords = map[UserRecordID]UserRecord{}

type MemoryRecordStore struct{}

func (m MemoryRecordStore) GetRecord(recordID UserRecordID) (UserRecord, error) {
	record := memoryRecords[recordID]
	if record.RegistrationState == nil {
		record.RegistrationState = NotRegistered{}
	}
	return record, nil
}

func (m MemoryRecordStore) WriteRecord(recordID UserRecordID, record UserRecord) error {
	memoryRecords[recordID] = record
	return nil
}
