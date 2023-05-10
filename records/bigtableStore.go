package records

import (
	"context"
	"errors"
	"os"

	"cloud.google.com/go/bigtable"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/juicebox-software-realm/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BigtableRecordStore struct {
	client    *bigtable.Client
	tableName string
}

const familyName = "f"
const columnName = "v"

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
	defer admin.Close()

	tableName := types.JuiceboxRealmDatabasePrefix + realmID.String()

	config := bigtable.TableConf{
		TableID: tableName,
		Families: map[string]bigtable.GCPolicy{
			familyName: bigtable.MaxVersionsPolicy(1),
		},
	}

	if err := admin.CreateTableFromConf(ctx, &config); err != nil {
		if status.Code(err) != codes.AlreadyExists {
			return nil, err
		}
	}

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

func (bt BigtableRecordStore) GetRecord(ctx context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	userRecord := DefaultUserRecord()

	table := bt.client.Open(bt.tableName)

	row, err := table.ReadRow(ctx, string(recordID))
	if err != nil {
		return userRecord, nil, err
	}

	family, ok := row[familyName]
	if !ok {
		// no stored record yet
		return userRecord, nil, nil
	}

	readRecord := family[0]
	serializedUserRecord := readRecord.Value

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		return userRecord, readRecord, err
	}

	return userRecord, readRecord, nil
}

func (bt BigtableRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	table := bt.client.Open(bt.tableName)

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return err
	}

	mut := bigtable.NewMutation()
	mut.DeleteCellsInFamily(familyName)
	mut.Set(familyName, columnName, bigtable.ServerTime, serializedUserRecord)

	var conditionalMutation *bigtable.Mutation

	if readRecord == nil {
		filter := bigtable.ChainFilters(
			bigtable.FamilyFilter(familyName),
			bigtable.ColumnFilter(columnName),
		)
		conditionalMutation = bigtable.NewCondMutation(filter, nil, mut)
	} else {
		readRecord, ok := readRecord.(bigtable.ReadItem)
		if !ok {
			return errors.New("read record was of unexpected type")
		}
		filter := bigtable.ChainFilters(
			bigtable.FamilyFilter(familyName),
			bigtable.ColumnFilter(columnName),
			// only allow changes if the record's timestamp has remained unchanged (to the millisecond)
			bigtable.TimestampRangeFilterMicros(readRecord.Timestamp, readRecord.Timestamp+1000),
		)
		conditionalMutation = bigtable.NewCondMutation(filter, mut, nil)
	}

	var success bool
	opt := bigtable.GetCondMutationResult(&success)

	err = table.Apply(ctx, string(recordID), conditionalMutation, opt)
	if err != nil {
		return err
	}

	if !success {
		return errors.New("failed to write to bigtable, record mutated since read")
	}

	return nil
}
