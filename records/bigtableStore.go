package records

import (
	"context"
	"encoding/hex"
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

func (bt BigtableRecordStore) GetRecord(recordID UserRecordID) (UserRecord, interface{}, error) {
	userRecord := DefaultUserRecord()

	table := bt.client.Open(bt.tableName)

	row, err := table.ReadRow(context.Background(), string(recordID))
	if err != nil {
		return userRecord, nil, err
	}

	family, ok := row[familyName]
	if !ok {
		// no stored record yet
		return userRecord, nil, nil
	}

	readRecord := string(family[0].Value)

	serializedUserRecord, err := hex.DecodeString(readRecord)
	if err != nil {
		return userRecord, readRecord, nil
	}

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		return userRecord, readRecord, err
	}

	return userRecord, readRecord, nil
}

func (bt BigtableRecordStore) WriteRecord(recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	table := bt.client.Open(bt.tableName)

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return err
	}

	mut := bigtable.NewMutation()
	mut.DeleteCellsInFamily(familyName)
	mut.Set(familyName, columnName, bigtable.Timestamp(0), []byte(hex.EncodeToString(serializedUserRecord)))

	var conditionalMutation *bigtable.Mutation

	if readRecord == nil {
		filter := bigtable.ChainFilters(
			bigtable.FamilyFilter(familyName),
			bigtable.ColumnFilter(columnName),
		)
		conditionalMutation = bigtable.NewCondMutation(filter, nil, mut)
	} else {
		readRecord, ok := readRecord.(string)
		if !ok {
			return errors.New("read record was of unexpected type")
		}

		filter := bigtable.ChainFilters(
			bigtable.FamilyFilter(familyName),
			bigtable.ColumnFilter(columnName),
			bigtable.ValueFilter(readRecord),
		)
		conditionalMutation = bigtable.NewCondMutation(filter, mut, nil)
	}

	var success bool
	opt := bigtable.GetCondMutationResult(&success)

	err = table.Apply(context.Background(), string(recordID), conditionalMutation, opt)
	if err != nil {
		return err
	}

	if !success {
		return errors.New("failed to write to bigtable, record mutated since read")
	}

	return nil
}
