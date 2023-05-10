package records

import (
	"context"
	"errors"
	"os"

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

func (db DynamoDbRecordStore) GetRecord(_ context.Context, recordID UserRecordID) (UserRecord, interface{}, error) {
	userRecord := DefaultUserRecord()

	input := &dynamodb.GetItemInput{
		TableName: aws.String(db.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			primaryKeyName: {
				S: aws.String(string(recordID)),
			},
		},
	}

	result, err := db.svc.GetItem(input)
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
		return userRecord, serializedUserRecord, err
	}

	return userRecord, serializedUserRecord, nil
}

func (db DynamoDbRecordStore) WriteRecord(_ context.Context, recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return err
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
		},
	}

	if readRecord == nil {
		input.ConditionExpression = aws.String("attribute_not_exists(#primaryKey)")
		input.ExpressionAttributeNames = map[string]*string{
			"#primaryKey": aws.String(primaryKeyName),
		}
	} else {
		readRecord, ok := readRecord.([]byte)
		if !ok {
			return errors.New("read record was of unexpected type")
		}

		input.ConditionExpression = aws.String("#columnName = :previousValue")
		input.ExpressionAttributeNames = map[string]*string{
			"#columnName": aws.String(userRecordAttributeName),
		}
		input.ExpressionAttributeValues = map[string]*dynamodb.AttributeValue{
			":previousValue": {
				B: readRecord,
			},
		}
	}

	_, err = db.svc.PutItem(input)
	if err != nil {
		return err
	}

	return nil
}
