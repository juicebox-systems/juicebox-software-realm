package secrets

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

type MongoSecretsManager struct {
	client       *mongo.Client
	databaseName string
}

const secretsCollection string = "tenantSecrets"
const secretsVersionKey string = "version"
const secretsSecretKey string = "secret"

func NewMongoSecretsManager(ctx context.Context, realmID types.RealmID) (SecretsManager, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"NewMongoSecretsManager",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemMongoDB),
	)
	defer span.End()

	urlString := os.Getenv("MONGO_URL")
	if urlString == "" {
		err := errors.New("unexpectedly missing MONGO_URL")
		return nil, otel.RecordOutcome(err, span)
	}

	url, err := url.Parse(urlString)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	databaseName := types.JuiceboxRealmDatabasePrefix + realmID.String()
	if len(url.Path) > 1 {
		databaseName = url.Path[1:]
	}

	clientOptions := options.Client().ApplyURI(urlString)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	return newCachingSecretsManager(&MongoSecretsManager{
		client:       client,
		databaseName: databaseName,
	}), nil
}

func (sm *MongoSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"GetSecret",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemMongoDB),
	)
	defer span.End()

	database := sm.client.Database(sm.databaseName)
	collection := database.Collection(secretsCollection)

	var result bson.M
	err := collection.FindOne(
		ctx,
		bson.M{"_id": name, secretsVersionKey: version},
	).Decode(&result)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	secret, ok := result[secretsSecretKey]
	if !ok {
		err := errors.New("secret unexpectedly missing 'secret' key")
		return nil, otel.RecordOutcome(err, span)
	}

	switch secret := secret.(type) {
	case string:
		return []byte(secret), nil
	case primitive.Binary:
		return secret.Data, nil
	}

	err = errors.New("unexpected secret type")
	return nil, otel.RecordOutcome(err, span)
}
