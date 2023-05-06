package records

import (
	"errors"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type DynamoDbRecordStore struct {
	svc       *dynamodb.DynamoDB
	tableName string
}

const primaryKeyName string = "recordId"
const attributedName string = "serializedUserRecord"

func NewDynamoDbRecordStore(realmId uuid.UUID) (*DynamoDbRecordStore, error) {
	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		return nil, errors.New("unexpectedly missing AWS_REGION_NAME")
	}

	session, error := session.NewSession(&aws.Config{
		Region: &region,
	})
	if error != nil {
		return nil, error
	}

	svc := dynamodb.New(session)

	return &DynamoDbRecordStore{
		svc:       svc,
		tableName: realmId.String(),
	}, nil
}

func (db DynamoDbRecordStore) GetRecord(recordId UserRecordId) (UserRecord, error) {
	userRecord := UserRecord{
		RegistrationState: NotRegistered{},
	}

	input := &dynamodb.GetItemInput{
		TableName: aws.String(db.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			primaryKeyName: {
				S: aws.String(string(recordId)),
			},
		},
	}

	result, error := db.svc.GetItem(input)
	if error != nil {
		return userRecord, error
	}

	if len(result.Item) == 0 {
		// no stored record yet
		return userRecord, nil
	}

	attributeValue, ok := result.Item[attributedName]
	if !ok {
		return userRecord, errors.New("failed to read attribute")
	}

	serializedUserRecord := attributeValue.B

	error = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if error != nil {
		return userRecord, error
	}

	return userRecord, nil
}

func (db DynamoDbRecordStore) WriteRecord(recordId UserRecordId, record UserRecord) error {
	serializedUserRecord, error := cbor.Marshal(record)
	if error != nil {
		return error
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(db.tableName),
		Item: map[string]*dynamodb.AttributeValue{
			primaryKeyName: {
				S: aws.String(string(recordId)),
			},
			attributedName: {
				B: serializedUserRecord,
			},
		},
	}

	_, error = db.svc.PutItem(input)
	if error != nil {
		return error
	}

	return nil
}
