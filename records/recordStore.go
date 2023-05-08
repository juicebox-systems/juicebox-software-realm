package records

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/juicebox-software-realm/types"
)

type RecordStore interface {
	GetRecord(recordID UserRecordID) (UserRecord, error)
	WriteRecord(recordID UserRecordID, record UserRecord) error
}

func NewRecordStore(provider types.ProviderName, realmID uuid.UUID) (RecordStore, error) {
	switch provider {
	case types.GCP:
		return NewBigtableRecordStore(realmID)
	case types.Memory:
		return MemoryRecordStore{}, nil
	case types.AWS:
		return NewDynamoDbRecordStore(realmID)
	case types.Mongo:
		return NewMongoRecordStore(realmID)
	}
	return nil, fmt.Errorf("unexpected provider %v", provider)
}
