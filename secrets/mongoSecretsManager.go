package secrets

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoSecretsManager struct {
	client       *mongo.Client
	databaseName string
}

const secretsCollection string = "tenantSecrets"
const secretsVersionKey string = "version"
const secretsSecretKey string = "secret"

func NewMongoSecretsManager(realmID uuid.UUID) (*MongoSecretsManager, error) {
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

	return &MongoSecretsManager{
		client:       client,
		databaseName: databaseName,
	}, nil
}

func (sm MongoSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	database := sm.client.Database(sm.databaseName)
	collection := database.Collection(secretsCollection)

	var result bson.M
	err := collection.FindOne(
		ctx,
		bson.M{"_id": name, secretsVersionKey: version},
	).Decode(&result)
	if err != nil {
		return nil, err
	}

	secret, ok := result[secretsSecretKey]
	if !ok {
		return nil, errors.New("secret unexpectedly missing 'secret' key")
	}

	switch secret := secret.(type) {
	case string:
		return []byte(secret), nil
	case primitive.Binary:
		return secret.Data, nil
	}

	return nil, errors.New("unexpected secret type")
}
