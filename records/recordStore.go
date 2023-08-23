package records

import (
	"context"
	"fmt"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/codes"
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

func NewRecordStore(ctx context.Context, provider types.ProviderName, realmID types.RealmID) (RecordStore, error) {
	ctx, span := otel.StartSpan(ctx, "NewRecordStore")
	defer span.End()

	switch provider {
	case types.GCP:
		return NewBigtableRecordStore(ctx, realmID)
	case types.Memory:
		return MemoryRecordStore{}, nil
	case types.AWS:
		return NewDynamoDbRecordStore(ctx, realmID)
	case types.Mongo:
		return NewMongoRecordStore(ctx, realmID)
	}

	err := fmt.Errorf("unexpected provider %v", provider)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return nil, err
}
