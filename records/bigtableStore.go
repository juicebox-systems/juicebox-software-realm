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

func NewBigtableRecordStore(realmID uuid.UUID) (*BigtableRecordStore, error) {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return nil, errors.New("unexpectedly missing GCP_PROJECT_ID")
	}

	instanceID := os.Getenv("BIGTABLE_INSTANCE_ID")
	if instanceID == "" {
		return nil, errors.New("unexpectedly missing BIGTABLE_INSTANCE_ID")
	}

	ctx := context.Background()

	admin, err := bigtable.NewAdminClient(ctx, projectID, instanceID)
	if err != nil {
		return nil, err
	}

	tableName := realmID.String()

	if err := admin.CreateTable(ctx, tableName); err != nil {
		if !strings.HasPrefix(err.Error(), "rpc error: code = AlreadyExists") {
			return nil, err
		}
	}

	if err := admin.CreateColumnFamily(ctx, tableName, familyName); err != nil {
		if !strings.HasPrefix(err.Error(), "rpc error: code = AlreadyExists") {
			return nil, err
		}
	}

	admin.Close()

	client, err := bigtable.NewClient(ctx, projectID, instanceID)
	if err != nil {
		return nil, err
	}

	return &BigtableRecordStore{
		client:    client,
		tableName: tableName,
	}, nil
}

func (bt BigtableRecordStore) Close() {
	bt.client.Close()
}

func (bt BigtableRecordStore) GetRecord(recordID UserRecordID) (UserRecord, error) {
	userRecord := UserRecord{
		RegistrationState: NotRegistered{},
	}

	table := bt.client.Open(bt.tableName)

	row, err := table.ReadRow(context.Background(), string(recordID))
	if err != nil {
		return userRecord, err
	}

	family, ok := row[familyName]
	if !ok {
		// no stored record yet
		return userRecord, nil
	}

	serializedUserRecord := family[0].Value

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		return userRecord, err
	}

	return userRecord, nil
}

func (bt BigtableRecordStore) WriteRecord(recordID UserRecordID, record UserRecord) error {
	table := bt.client.Open(bt.tableName)

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return err
	}

	mut := bigtable.NewMutation()
	mut.DeleteCellsInFamily(familyName)
	mut.Set(familyName, columnName, bigtable.Now().TruncateToMilliseconds(), serializedUserRecord)

	err = table.Apply(context.Background(), string(recordID), mut)
	if err != nil {
		return err
	}

	return nil
}
