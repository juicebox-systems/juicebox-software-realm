package records

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/juicebox-software-realm/types"
)

// RecordStore represents a generic interface into the
// database storage provider of your choice.
type RecordStore interface {
	// Returns a processed UserRecord deserialized from the database or a default
	// record if nothing is currently stored. Also returns the raw record read
	// from the database – this must be passed to WriteRecord to ensure atomic operation.
	GetRecord(ctx context.Context, recordID UserRecordID) (UserRecord, interface{}, error)
	// The write will only be performed if the record in the database still matches
	// the record that was read.
	WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error
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
