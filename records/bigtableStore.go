package records

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"cloud.google.com/go/bigtable"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/juicebox-software-realm/otel"
	"github.com/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BigtableRecordStore struct {
	client    *bigtable.Client
	tableName string
}

const familyName = "f"

func NewBigtableRecordStore(ctx context.Context, realmID uuid.UUID) (*BigtableRecordStore, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"NewBigtableRecordStore",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemKey.String("bigtable")),
	)
	defer span.End()

	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		err := errors.New("unexpectedly missing GCP_PROJECT_ID")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	instanceID := os.Getenv("BIGTABLE_INSTANCE_ID")
	if instanceID == "" {
		err := errors.New("unexpectedly missing BIGTABLE_INSTANCE_ID")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	admin, err := bigtable.NewAdminClient(ctx, projectID, instanceID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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
		if status.Code(err) != grpccodes.AlreadyExists {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	client, err := bigtable.NewClient(ctx, projectID, instanceID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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
	ctx, span := otel.StartSpan(
		ctx,
		"GetRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemKey.String("bigtable")),
	)
	defer span.End()

	userRecord := DefaultUserRecord()

	table := bt.client.Open(bt.tableName)

	row, err := table.ReadRow(ctx, string(recordID))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return userRecord, readRecord, err
	}

	return userRecord, readRecord, nil
}

func (bt BigtableRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	ctx, span := otel.StartSpan(
		ctx,
		"WriteRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemKey.String("bigtable")),
	)
	defer span.End()

	table := bt.client.Open(bt.tableName)

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	var newVersion uint64
	var previousColumnName *string

	// If we read an existing record from the db, try and identify a version for it.
	// We'll use this version to ensure no-one has mutated this row since we read it.
	if readRecord != nil {
		readRecord, ok := readRecord.(bigtable.ReadItem)
		if !ok {
			err := errors.New("unexepected type for read record")
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		// the "Column" field actually contains family:column
		readColumnName := strings.TrimPrefix(readRecord.Column, familyName+":")

		previousVersion, err := strconv.ParseUint(readColumnName, 10, 64)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		newVersion = previousVersion + 1
		previousColumnName = &readColumnName
	}

	columnName := fmt.Sprint(newVersion)

	mut := bigtable.NewMutation()
	mut.DeleteCellsInFamily(familyName)
	mut.Set(familyName, columnName, bigtable.Timestamp(0), serializedUserRecord)

	var conditionalMutation *bigtable.Mutation

	if previousColumnName == nil {
		filter := bigtable.ChainFilters(
			bigtable.FamilyFilter(familyName),
			// ensure that no columns exist in the family
			bigtable.ColumnFilter(".*"),
		)
		conditionalMutation = bigtable.NewCondMutation(filter, nil, mut)
	} else {
		filter := bigtable.ChainFilters(
			bigtable.FamilyFilter(familyName),
			// ensure that the previous column version still exists
			bigtable.ColumnFilter(*previousColumnName),
		)
		conditionalMutation = bigtable.NewCondMutation(filter, mut, nil)
	}

	var conditionalResult bool
	opt := bigtable.GetCondMutationResult(&conditionalResult)

	err = table.Apply(ctx, string(recordID), conditionalMutation, opt)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// if we had a previous column, we want the condition to be true
	// if we did not have a previous column, we want it to be false
	desiredConditionalResult := previousColumnName != nil
	if conditionalResult != desiredConditionalResult {
		err := errors.New("failed to write to bigtable, record mutated since read")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
