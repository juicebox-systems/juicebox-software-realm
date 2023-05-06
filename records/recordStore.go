package records

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/juicebox-software-realm/types"
)

type RecordStore interface {
	GetRecord(recordId UserRecordId) (UserRecord, error)
	WriteRecord(recordId UserRecordId, record UserRecord) error
}

func NewRecordStore(provider types.ProviderName, realmId uuid.UUID) (RecordStore, error) {
	switch provider {
	case types.GCP:
		return NewBigtableRecordStore(realmId)
	case types.Memory:
		return MemoryRecordStore{}, nil
	case types.AWS:
		return MemoryRecordStore{}, nil
	}
	return nil, fmt.Errorf("Unexpected provider %v", provider)
}
