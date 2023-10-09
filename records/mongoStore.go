package records

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

type MongoRecordStore struct {
	client       *mongo.Client
	databaseName string
}

const userRecordsCollection string = "userRecords"
const serializedUserRecordKey string = "serializedUserRecord"
const versionKey string = "version"

func NewMongoRecordStore(ctx context.Context, realmID types.RealmID) (*MongoRecordStore, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"NewMongoRecordStore",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemMongoDB),
	)
	defer span.End()

	urlString := os.Getenv("MONGO_URL")
	if urlString == "" {
		err := errors.New("unexpectedly missing MONGO_URL")
		return nil, otel.RecordOutcome(err, span)
	}

	url, err := url.Parse(urlString)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	databaseName := types.JuiceboxRealmDatabasePrefix + realmID.String()

	// mongodb urls traditionally end in "/database", so we extract any
	// provided database name here (stripping the leading "/").
	if len(url.Path) > 1 {
		databaseName = url.Path[1:]
	}

	clientOptions := options.Client().ApplyURI(urlString)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	err = client.Database(databaseName).CreateCollection(ctx, userRecordsCollection)
	if err != nil {
		// ignore the "NamespaceExists" error code
		if mErr, ok := err.(mongo.CommandError); !ok || !mErr.HasErrorCode(48) {
			return nil, otel.RecordOutcome(err, span)
		}
	}

	return &MongoRecordStore{
		client:       client,
		databaseName: databaseName,
	}, nil
}

func (m MongoRecordStore) GetRecord(ctx context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"GetRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemMongoDB),
	)
	defer span.End()

	userRecord := DefaultUserRecord()

	database := m.client.Database(m.databaseName)
	collection := database.Collection(userRecordsCollection)

	var result bson.M
	err := collection.FindOne(
		ctx,
		bson.M{"_id": recordID},
	).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// no stored record yet
			return userRecord, nil, nil
		}
		return userRecord, nil, otel.RecordOutcome(err, span)
	}

	record, ok := result[serializedUserRecordKey]
	if !ok {
		err := errors.New("result unexpectedly missing 'serializedUserRecord' key")
		return userRecord, result, otel.RecordOutcome(err, span)
	}

	primitiveBinaryRecord, ok := record.(primitive.Binary)
	if !ok {
		err := errors.New("user record was of wrong type")
		return userRecord, result, otel.RecordOutcome(err, span)
	}

	serializedUserRecord := primitiveBinaryRecord.Data

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		return userRecord, result, otel.RecordOutcome(err, span)
	}

	return userRecord, result, nil
}

func (m MongoRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	ctx, span := otel.StartSpan(
		ctx,
		"WriteRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemMongoDB),
	)
	defer span.End()

	database := m.client.Database(m.databaseName)
	collection := database.Collection(userRecordsCollection)

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return otel.RecordOutcome(err, span)
	}

	// mongo doesn't support unsigned integers, but it supports 64-bit signed
	// integers. since this version can safely overflow we don't care.
	var newVersion int64
	var previousVersion *int64

	// If we read an existing record from the db, try and identify a version for it.
	// We'll use this version to ensure no-one has mutated this row since we read it.
	if readRecord != nil {
		readRecord, ok := readRecord.(primitive.M)
		if !ok {
			err := errors.New("unexepected type for read record")
			return otel.RecordOutcome(err, span)
		}

		record, ok := readRecord[versionKey]
		if !ok {
			err := errors.New("read record unexpectedly missing version attribute")
			return otel.RecordOutcome(err, span)
		}

		v, ok := record.(int64)
		if !ok {
			err := errors.New("read record version key was of wrong type")
			return otel.RecordOutcome(err, span)
		}

		newVersion = v + 1
		previousVersion = &v
	}

	_, err = collection.UpdateOne(
		ctx,
		// lookup a record based on the recordID and previousVersion (or nil version)
		bson.M{
			"_id":      recordID,
			versionKey: previousVersion,
		},
		// and set these keys on that record if we find it
		bson.M{
			"$set": bson.M{
				"_id":                   recordID,
				serializedUserRecordKey: serializedUserRecord,
				versionKey:              newVersion,
			},
		},
		// if we find no record set the keys on a new record if previousVersion was nil
		options.Update().SetUpsert(previousVersion == nil),
	)

	if err != nil {
		return otel.RecordOutcome(err, span)
	}
	return nil
}
