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

func NewMongoRecordStore(realmId uuid.UUID) (*MongoRecordStore, error) {
	urlString := os.Getenv("MONGO_URL")
	if urlString == "" {
		return nil, errors.New("unexpectedly missing MONGO_URL")
	}

	url, error := url.Parse(urlString)
	if error != nil {
		return nil, error
	}

	databaseName := realmId.String()
	if len(url.Path) > 1 {
		databaseName = url.Path[1:]
	}

	clientOptions := options.Client().ApplyURI(urlString)
	client, error := mongo.Connect(context.Background(), clientOptions)
	if error != nil {
		return nil, error
	}

	error = client.Database(databaseName).CreateCollection(context.Background(), userRecordsCollection)
	if error != nil {
		if !strings.HasPrefix(error.Error(), "(NamespaceExists)") {
			return nil, error
		}
	}

	return &MongoRecordStore{
		client:       client,
		databaseName: databaseName,
	}, nil
}

func (m MongoRecordStore) GetRecord(recordId UserRecordId) (UserRecord, error) {
	userRecord := UserRecord{
		RegistrationState: NotRegistered{},
	}

	database := m.client.Database(m.databaseName)
	collection := database.Collection(userRecordsCollection)

	var result bson.M
	error := collection.FindOne(
		context.Background(),
		bson.M{"_id": recordId},
	).Decode(&result)
	if error != nil {
		if strings.HasPrefix(error.Error(), "mongo: no documents in result") {
			// no stored record yet
			return userRecord, nil
		}
		fmt.Printf("what? %+v\n", error)
		return userRecord, error
	}

	record, ok := result[serializedUserRecordKey]
	if !ok {
		return userRecord, errors.New("secret unexpectedly missing 'secret' key")
	}

	primitiveBinaryRecord, ok := record.(primitive.Binary)
	if !ok {
		return userRecord, errors.New("user record was of wrong type")
	}

	serializedUserRecord := primitiveBinaryRecord.Data

	error = cbor.Unmarshal(serializedUserRecord, &userRecord)
	if error != nil {
		return userRecord, error
	}

	return userRecord, nil
}

func (m MongoRecordStore) WriteRecord(recordId UserRecordId, record UserRecord) error {
	database := m.client.Database(m.databaseName)
	collection := database.Collection(userRecordsCollection)

	serializedUserRecord, error := cbor.Marshal(record)
	if error != nil {
		return error
	}

	_, error = collection.UpdateOne(
		context.Background(),
		bson.M{"_id": recordId},
		bson.M{
			"$set": bson.M{
				"_id":                   recordId,
				serializedUserRecordKey: serializedUserRecord,
			},
		},
		options.Update().SetUpsert(true),
	)

	if error != nil {
		return error
	}

	return nil
}
