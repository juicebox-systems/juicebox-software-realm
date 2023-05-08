package secrets

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/golang-jwt/jwt"
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

func NewMongoSecretsManager(realmId uuid.UUID) (*MongoSecretsManager, error) {
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

	return &MongoSecretsManager{
		client:       client,
		databaseName: databaseName,
	}, nil
}

func (sm MongoSecretsManager) GetSecret(name string, version uint64) ([]byte, error) {
	database := sm.client.Database(sm.databaseName)
	collection := database.Collection(secretsCollection)

	var result bson.M
	error := collection.FindOne(
		context.Background(),
		bson.M{"_id": name, secretsVersionKey: version},
	).Decode(&result)
	if error != nil {
		return nil, error
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

func (sm MongoSecretsManager) GetJWTSigningKey(token *jwt.Token) (interface{}, error) {
	name, version, error := ParseKid(token)
	if error != nil {
		return nil, error
	}

	key, error := sm.GetSecret(*name, *version)
	if error != nil {
		return nil, errors.New("no signing key for jwt")
	}

	return key, nil
}
