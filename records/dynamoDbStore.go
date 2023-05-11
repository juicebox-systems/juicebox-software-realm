package records

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/juicebox-software-realm/trace"
	"github.com/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type DynamoDbRecordStore struct {
	svc       *dynamodb.DynamoDB
	tableName string
}

const primaryKeyName string = "recordId"
const userRecordAttributeName string = "serializedUserRecord"
const versionAttributeName string = "version"

func NewDynamoDbRecordStore(ctx context.Context, realmID uuid.UUID) (*DynamoDbRecordStore, error) {
	_, span := trace.StartSpan(
		ctx,
		"NewDynamoDbRecordStore",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(semconv.DBSystemDynamoDB),
	)
	defer span.End()

	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		err := errors.New("unexpectedly missing AWS_REGION_NAME")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	session, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	svc := dynamodb.New(session)

	tableName := types.JuiceboxRealmDatabasePrefix + realmID.String()

	return &DynamoDbRecordStore{
		svc:       svc,
		tableName: tableName,
	}, nil
}

func (db DynamoDbRecordStore) GetRecord(ctx context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	ctx, span := trace.StartSpan(
		ctx,
		"GetRecord",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(semconv.DBSystemDynamoDB),
	)
	defer span.End()

	userRecord := DefaultUserRecord()

	input := &dynamodb.GetItemInput{
		TableName: aws.String(db.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			primaryKeyName: {
				S: aws.String(string(recordID)),
			},
		},
	}

	result, err := db.svc.GetItemWithContext(ctx, input)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return userRecord, nil, err
	}

	if len(result.Item) == 0 {
		// no stored record yet
		return userRecord, nil, nil
	}

	attributeValue, ok := result.Item[userRecordAttributeName]
	if !ok {
		err := errors.New("failed to read attribute")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return userRecord, nil, err
	}

	serializedUserRecord := attributeValue.B

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return userRecord, result.Item, err
	}

	return userRecord, result.Item, nil
}

func (db DynamoDbRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	ctx, span := trace.StartSpan(
		ctx,
		"WriteRecord",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(semconv.DBSystemDynamoDB),
	)
	defer span.End()

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	var newVersion uint64
	var previousVersion *uint64

	// If we read an existing record from the db, try and identify a version for it.
	// We'll use this version to ensure no-one has mutated this row since we read it.
	if readRecord != nil {
		readRecord, ok := readRecord.(map[string]*dynamodb.AttributeValue)
		if !ok {
			err := errors.New("unexepected type for read record")
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		versionAttribute, ok := readRecord[versionAttributeName]
		if !ok {
			err := errors.New("read record unexpectedly missing version attribute")
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		if versionAttribute.N == nil {
			err := errors.New("read record version attribute is unexpected type")
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		v, err := strconv.ParseUint(*versionAttribute.N, 10, 64)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}

		newVersion = v + 1
		previousVersion = &v
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(db.tableName),
		Item: map[string]*dynamodb.AttributeValue{
			primaryKeyName: {
				S: aws.String(string(recordID)),
			},
			userRecordAttributeName: {
				B: serializedUserRecord,
			},
			versionAttributeName: {
				N: aws.String(fmt.Sprint(newVersion)),
			},
		},
	}

	if previousVersion == nil {
		input.ConditionExpression = aws.String("attribute_not_exists(#primaryKey)")
		input.ExpressionAttributeNames = map[string]*string{
			"#primaryKey": aws.String(primaryKeyName),
		}
	} else {
		input.ConditionExpression = aws.String("#version = :previousVersion")
		input.ExpressionAttributeNames = map[string]*string{
			"#version": aws.String(versionAttributeName),
		}
		input.ExpressionAttributeValues = map[string]*dynamodb.AttributeValue{
			":previousVersion": {
				N: aws.String(fmt.Sprint(*previousVersion)),
			},
		}
	}

	_, err = db.svc.PutItemWithContext(ctx, input)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
