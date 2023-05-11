package secrets

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/google/uuid"
	"github.com/juicebox-software-realm/trace"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type MongoSecretsManager struct {
	client       *mongo.Client
	databaseName string
}

const secretsCollection string = "tenantSecrets"
const secretsVersionKey string = "version"
const secretsSecretKey string = "secret"

func NewMongoSecretsManager(ctx context.Context, realmID uuid.UUID) (*MongoSecretsManager, error) {
	ctx, span := trace.StartSpan(
		ctx,
		"NewMongoSecretsManager",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(semconv.DBSystemMongoDB),
	)
	defer span.End()

	urlString := os.Getenv("MONGO_URL")
	if urlString == "" {
		err := errors.New("unexpectedly missing MONGO_URL")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	url, err := url.Parse(urlString)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	databaseName := realmID.String()
	if len(url.Path) > 1 {
		databaseName = url.Path[1:]
	}

	clientOptions := options.Client().ApplyURI(urlString)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &MongoSecretsManager{
		client:       client,
		databaseName: databaseName,
	}, nil
}

func (sm MongoSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	ctx, span := trace.StartSpan(
		ctx,
		"GetSecret",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
		oteltrace.WithAttributes(semconv.DBSystemMongoDB),
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
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	secret, ok := result[secretsSecretKey]
	if !ok {
		err := errors.New("secret unexpectedly missing 'secret' key")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	switch secret := secret.(type) {
	case string:
		return []byte(secret), nil
	case primitive.Binary:
		return secret.Data, nil
	}

	err = errors.New("unexpected secret type")
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return nil, err
}
