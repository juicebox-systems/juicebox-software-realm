package records

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoRecordStore struct {
	client       *mongo.Client
	databaseName string
}

const userRecordsCollection string = "userRecords"
const serializedUserRecordKey string = "serializedUserRecord"

func NewMongoRecordStore(realmID uuid.UUID) (*MongoRecordStore, error) {
	urlString := os.Getenv("MONGO_URL")
	if urlString == "" {
		return nil, errors.New("unexpectedly missing MONGO_URL")
	}

	url, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}

	databaseName := realmID.String()
	if len(url.Path) > 1 {
		databaseName = url.Path[1:]
	}

	clientOptions := options.Client().ApplyURI(urlString)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, err
	}

	err = client.Database(databaseName).CreateCollection(context.Background(), userRecordsCollection)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "(NamespaceExists)") {
			return nil, err
		}
	}

	return &MongoRecordStore{
		client:       client,
		databaseName: databaseName,
	}, nil
}

func (m MongoRecordStore) GetRecord(recordID UserRecordID) (UserRecord, interface{}, error) {
	userRecord := DefaultUserRecord()

	database := m.client.Database(m.databaseName)
	collection := database.Collection(userRecordsCollection)

	var result bson.M
	err := collection.FindOne(
		context.Background(),
		bson.M{"_id": recordID},
	).Decode(&result)
	if err != nil {
		if strings.HasPrefix(err.Error(), "mongo: no documents in result") {
			// no stored record yet
			return userRecord, nil, nil
		}
		fmt.Printf("what? %+v\n", err)
		return userRecord, nil, err
	}

	record, ok := result[serializedUserRecordKey]
	if !ok {
		return userRecord, nil, errors.New("secret unexpectedly missing 'secret' key")
	}

	primitiveBinaryRecord, ok := record.(primitive.Binary)
	if !ok {
		return userRecord, nil, errors.New("user record was of wrong type")
	}

	serializedUserRecord := primitiveBinaryRecord.Data

	err = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if err != nil {
		return userRecord, serializedUserRecord, err
	}

	return userRecord, serializedUserRecord, nil
}

func (m MongoRecordStore) WriteRecord(recordID UserRecordID, record UserRecord, readRecord interface{}) error {
	database := m.client.Database(m.databaseName)
	collection := database.Collection(userRecordsCollection)

	serializedUserRecord, err := cbor.Marshal(record)
	if err != nil {
		return err
	}

	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"_id": recordID, serializedUserRecordKey: readRecord},
		bson.M{
			"$set": bson.M{
				"_id":                   recordID,
				serializedUserRecordKey: serializedUserRecord,
			},
		},
		options.Update().SetUpsert(readRecord == nil),
	)

	if err != nil {
		return err
	}

	return nil
}
