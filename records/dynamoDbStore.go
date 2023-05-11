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
	"github.com/juicebox-software-realm/types"
)

type DynamoDbRecordStore struct {
	svc       *dynamodb.DynamoDB
	tableName string
}

const primaryKeyName string = "recordId"
const userRecordAttributeName string = "serializedUserRecord"
const versionAttributeName string = "version"

func NewDynamoDbRecordStore(realmID uuid.UUID) (*DynamoDbRecordStore, error) {
	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		return nil, errors.New("unexpectedly missing AWS_REGION_NAME")
	}

	session, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
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
		return userRecord, nil, err
	}

	if len(result.Item) == 0 {
		// no stored record yet
		return userRecord, nil, nil
	}

	attributeValue, ok := result.Item[userRecordAttributeName]
	if !ok {
		return userRecord, nil, errors.New("failed to read attribute")
	}

	serializedUserRecord := attributeValue.B

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		return userRecord, result.Item, err
	}

	return userRecord, result.Item, nil
}

func (db DynamoDbRecordStore) WriteRecord(ctx context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return err
	}

	var newVersion uint64
	var previousVersion *uint64

	// If we read an existing record from the db, try and identify a version for it.
	// We'll use this version to ensure no-one has mutated this row since we read it.
	if readRecord != nil {
		readRecord, ok := readRecord.(map[string]*dynamodb.AttributeValue)
		if !ok {
			return errors.New("unexepected type for read record")
		}

		versionAttribute, ok := readRecord[versionAttributeName]
		if !ok {
			return errors.New("read record unexpectedly missing version attribute")
		}

		if versionAttribute.N == nil {
			return errors.New("read record version attribute is unexpected type")
		}

		v, err := strconv.ParseUint(*versionAttribute.N, 10, 64)
		if err != nil {
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
		return err
	}

	return nil
}
