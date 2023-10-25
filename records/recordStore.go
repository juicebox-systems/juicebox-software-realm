package records

import (
	"context"
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
