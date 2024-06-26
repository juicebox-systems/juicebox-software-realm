package records

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

type DynamoDbRecordStore struct {
	svc       *dynamodb.Client
	tableName string
}

const primaryKeyName string = "recordId"
const userRecordAttributeName string = "serializedUserRecord"
const versionAttributeName string = "version"

func NewDynamoDbRecordStore(ctx context.Context, cfg aws.Config, realmID types.RealmID) (*DynamoDbRecordStore, error) {
	_, span := otel.StartSpan(
		ctx,
		"NewDynamoDbRecordStore",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemDynamoDB),
	)
	defer span.End()

	svc := dynamodb.NewFromConfig(cfg)
	tableName := types.JuiceboxRealmDatabasePrefix + realmID.String()

	return &DynamoDbRecordStore{
		svc:       svc,
		tableName: tableName,
	}, nil
}

func (db DynamoDbRecordStore) GetRecord(ctx context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"GetRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemDynamoDB),
	)
	defer span.End()

	userRecord := DefaultUserRecord()

	consistentRead := true
	input := &dynamodb.GetItemInput{
		TableName: aws.String(db.tableName),
		Key: map[string]ddbTypes.AttributeValue{
			primaryKeyName: &ddbTypes.AttributeValueMemberS{
				Value: string(recordID),
			},
		},
		ConsistentRead: &consistentRead,
	}

	result, err := db.svc.GetItem(ctx, input)
	if err != nil {
		return userRecord, nil, otel.RecordOutcome(err, span)
	}

	if len(result.Item) == 0 {
		// no stored record yet
		return userRecord, nil, nil
	}

	attributeValue, ok := result.Item[userRecordAttributeName]
	if !ok {
		err := errors.New("failed to read attribute")
		return userRecord, nil, otel.RecordOutcome(err, span)
	}

	binaryValue, ok := attributeValue.(*ddbTypes.AttributeValueMemberB)
	if !ok {
		err := errors.New("record should have a binary value but does not")
		return userRecord, nil, otel.RecordOutcome(err, span)
	}

	err = cbor.Unmarshal(binaryValue.Value, &userRecord)
	if err != nil {
		return userRecord, result.Item, otel.RecordOutcome(err, span)
	}

	return userRecord, result.Item, nil
}

func (db DynamoDbRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	ctx, span := otel.StartSpan(
		ctx,
		"WriteRecord",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemDynamoDB),
	)
	defer span.End()

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return otel.RecordOutcome(err, span)
	}

	var newVersion uint64
	var previousVersion *uint64

	// If we read an existing record from the db, try and identify a version for it.
	// We'll use this version to ensure no-one has mutated this row since we read it.
	if readRecord != nil {
		readRecord, ok := readRecord.(map[string]ddbTypes.AttributeValue)
		if !ok {
			err := errors.New("unexpected type for read record")
			return otel.RecordOutcome(err, span)
		}

		versionAttribute, ok := readRecord[versionAttributeName]
		if !ok {
			err := errors.New("read record unexpectedly missing version attribute")
			return otel.RecordOutcome(err, span)
		}

		versionValue, ok := versionAttribute.(*ddbTypes.AttributeValueMemberN)
		if !ok {
			err := errors.New("read record version attribute is unexpected type")
			return otel.RecordOutcome(err, span)
		}

		v, err := strconv.ParseUint(versionValue.Value, 10, 64)
		if err != nil {
			return otel.RecordOutcome(err, span)
		}

		newVersion = v + 1
		previousVersion = &v
	}

	input := &dynamodb.PutItemInput{
		TableName: &db.tableName,
		Item: map[string]ddbTypes.AttributeValue{
			primaryKeyName: &ddbTypes.AttributeValueMemberS{
				Value: string(recordID),
			},
			userRecordAttributeName: &ddbTypes.AttributeValueMemberB{
				Value: serializedUserRecord,
			},
			versionAttributeName: &ddbTypes.AttributeValueMemberN{
				Value: fmt.Sprint(newVersion),
			},
		},
	}

	if previousVersion == nil {
		input.ConditionExpression = aws.String("attribute_not_exists(#primaryKey)")
		input.ExpressionAttributeNames = map[string]string{
			"#primaryKey": primaryKeyName,
		}
	} else {
		input.ConditionExpression = aws.String("#version = :previousVersion")
		input.ExpressionAttributeNames = map[string]string{
			"#version": versionAttributeName,
		}
		input.ExpressionAttributeValues = map[string]ddbTypes.AttributeValue{
			":previousVersion": &ddbTypes.AttributeValueMemberN{
				Value: fmt.Sprint(*previousVersion),
			},
		}
	}

	_, err = db.svc.PutItem(ctx, input)
	return otel.RecordOutcome(err, span)
}
