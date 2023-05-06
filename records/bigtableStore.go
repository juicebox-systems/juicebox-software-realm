package records

import (
	"context"
	"errors"
	"os"
	"strings"

	"cloud.google.com/go/bigtable"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type BigtableRecordStore struct {
	client    *bigtable.Client
	tableName string
}

const familyName = "cf1"
const columnName = "serializedUserRecord"

func NewBigtableRecordStore(realmId uuid.UUID) (*BigtableRecordStore, error) {
	projectId := os.Getenv("GCP_PROJECT_ID")
	if projectId == "" {
		return nil, errors.New("Unexpectedly missing GCP_PROJECT_ID")
	}

	instanceId := os.Getenv("BIGTABLE_INSTANCE_ID")
	if instanceId == "" {
		return nil, errors.New("Unexpectedly missing BIGTABLE_INSTANCE_ID")
	}

	ctx := context.Background()

	admin, error := bigtable.NewAdminClient(ctx, projectId, instanceId)
	if error != nil {
		return nil, error
	}

	tableName := realmId.String()

	if error := admin.CreateTable(ctx, tableName); error != nil {
		if !strings.HasPrefix(error.Error(), "rpc error: code = AlreadyExists") {
			return nil, error
		}
	}

	if error := admin.CreateColumnFamily(ctx, tableName, familyName); error != nil {
		if !strings.HasPrefix(error.Error(), "rpc error: code = AlreadyExists") {
			return nil, error
		}
	}

	admin.Close()

	client, error := bigtable.NewClient(ctx, projectId, instanceId)
	if error != nil {
		return nil, error
	}

	return &BigtableRecordStore{
		client:    client,
		tableName: tableName,
	}, nil
}

func (bt BigtableRecordStore) Close() {
	bt.client.Close()
}

func (bt BigtableRecordStore) GetRecord(recordId UserRecordId) (UserRecord, error) {
	userRecord := UserRecord{
		RegistrationState: NotRegistered{},
	}

	table := bt.client.Open(bt.tableName)

	row, error := table.ReadRow(context.Background(), string(recordId))
	if error != nil {
		return userRecord, error
	}

	family, ok := row[familyName]
	if !ok {
		// no stored record yet
		return userRecord, nil
	}

	serializedUserRecord := family[0].Value

	error = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if error != nil {
		return userRecord, error
	}

	return userRecord, nil
}

func (bt BigtableRecordStore) WriteRecord(recordId UserRecordId, record UserRecord) error {
	table := bt.client.Open(bt.tableName)

	serializedUserRecord, error := cbor.Marshal(record)
	if error != nil {
		return error
	}

	mut := bigtable.NewMutation()
	mut.DeleteCellsInFamily(familyName)
	mut.Set(familyName, columnName, bigtable.Now().TruncateToMilliseconds(), serializedUserRecord)

	if error := table.Apply(context.Background(), string(recordId), mut); error != nil {
		return error
	}

	return nil
}
