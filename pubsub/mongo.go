package pubsub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

const collectionSuffix = "_events"

type mongoPubSub struct {
	client *mongo.Client
	db     *mongo.Database
}

func newMongoPubSub(ctx context.Context, realmID types.RealmID) (PubSub, attribute.KeyValue, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"newMongoPubSub",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBSystemMongoDB),
	)
	defer span.End()

	urlString := os.Getenv("MONGO_URL")
	if urlString == "" {
		err := errors.New("unexpectedly missing MONGO_URL")
		return nil, semconv.DBSystemMongoDB, recordOutcome(err, span)
	}

	url, err := url.Parse(urlString)
	if err != nil {
		return nil, semconv.DBSystemMongoDB, recordOutcome(err, span)
	}

	databaseName := types.JuiceboxRealmDatabasePrefix + realmID.String()

	// mongodb urls traditionally end in "/database", so we extract any
	// provided database name here (stripping the leading "/").
	if len(url.Path) > 1 {
		databaseName = url.Path[1:]
	}

	clientOptions := options.Client().ApplyURI(urlString)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, semconv.DBSystemMongoDB, recordOutcome(err, span)
	}
	database := client.Database(databaseName)

	return &mongoPubSub{
		client: client,
		db:     database,
	}, semconv.DBSystemMongoDB, nil
}

func (m *mongoPubSub) Ack(ctx context.Context, _ types.RealmID, tenant string, ids []string) error {
	collection := m.db.Collection(tenant + collectionSuffix)
	objectIDs := make([]primitive.ObjectID, len(ids))
	var err error
	for i := range ids {
		objectIDs[i], err = primitive.ObjectIDFromHex(ids[i])
		if err != nil {
			return types.NewHTTPError(http.StatusBadRequest, fmt.Errorf("invalid ack id '%s': %s", ids[i], err))
		}
	}
	res, err := collection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": objectIDs}})
	if err != nil {
		return types.NewHTTPError(http.StatusInternalServerError, err)
	}
	missing := int64(len(objectIDs)) - res.DeletedCount
	if missing != 0 {
		return types.NewHTTPError(http.StatusBadRequest, fmt.Errorf("%d ack id's were invalid", missing))
	}
	return nil
}

func (m *mongoPubSub) Publish(ctx context.Context, _ types.RealmID, tenant string, event EventMessage) error {
	collection := m.db.Collection(tenant + collectionSuffix)
	eventTTLSecs := int32(7 * 24 * 60 * 60)
	_, err := collection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "created", Value: 1}},
		Options: &options.IndexOptions{ExpireAfterSeconds: &eventTTLSecs},
	})
	if err != nil {
		return err
	}
	me := mongoEventMessage{
		Event:   event,
		Created: time.Now(),
	}
	_, err = collection.InsertOne(ctx, me)
	return types.NewHTTPError(http.StatusInternalServerError, err)
}

func (m *mongoPubSub) Pull(ctx context.Context, _ types.RealmID, tenant string, max uint16) ([]responses.TenantLogEntry, error) {
	collection := m.db.Collection(tenant + collectionSuffix)
	max64 := int64(max)
	opts := options.FindOptions{
		Limit: &max64,
	}
	// Skip anything that has been pulled in the last 10 seconds.
	ackWindow := time.Now().Add(-time.Second * 10)
	rows, err := collection.Find(ctx,
		bson.M{"$or": bson.A{
			bson.M{"last_pulled": bson.M{"$eq": primitive.Null{}}},
			bson.M{"last_pulled": bson.M{"$lt": ackWindow}},
		}}, &opts)
	if err != nil {
		return nil, types.NewHTTPError(http.StatusInternalServerError, err)
	}
	defer rows.Close(ctx)

	results := []responses.TenantLogEntry{}
	ids := []primitive.ObjectID{}
	for rows.Next(ctx) {
		var e mongoEventMessage
		if err := rows.Decode(&e); err != nil {
			return nil, types.NewHTTPError(http.StatusInternalServerError, err)
		}
		loge := responses.TenantLogEntry{
			ID:         e.ID.Hex(),
			Ack:        e.ID.Hex(),
			When:       e.Created,
			UserID:     e.Event.User,
			Event:      e.Event.Event,
			NumGuesses: e.Event.NumGuesses,
			GuessCount: e.Event.GuessCount,
		}
		results = append(results, loge)
		ids = append(ids, e.ID)
	}
	_, err = collection.UpdateMany(ctx, bson.M{"_id": bson.M{"$in": ids}}, bson.M{"$currentDate": bson.M{"last_pulled": false}})
	if err != nil {
		return nil, types.NewHTTPError(http.StatusInternalServerError, err)
	}
	return results, nil
}

type mongoEventMessage struct {
	Event   EventMessage       `bson:"event"`
	ID      primitive.ObjectID `bson:"_id,omitempty"`
	Created time.Time          `bson:"created"`
}
