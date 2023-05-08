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

	return &DynamoDbRecordStore{
		svc:       svc,
		tableName: realmID.String(),
	}, nil
}

func (db DynamoDbRecordStore) GetRecord(recordID UserRecordID) (UserRecord, error) {
	userRecord := UserRecord{
		RegistrationState: NotRegistered{},
	}

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
		return userRecord, err
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

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		return userRecord, err
	}

	return userRecord, nil
}

func (db DynamoDbRecordStore) WriteRecord(recordID UserRecordID, record UserRecord) error {
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
			attributedName: {
				B: serializedUserRecord,
			},
		},
	}

	_, err = db.svc.PutItem(input)
	if err != nil {
		return err
	}

	return nil
}
