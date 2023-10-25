package pubsub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	gcp_pubsub "cloud.google.com/go/pubsub/apiv1"
	"cloud.google.com/go/pubsub/apiv1/pubsubpb"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type gcpPubSub struct {
	project   string
	subClient *gcp_pubsub.SubscriberClient
	pubClient *gcp_pubsub.PublisherClient
}

var msgType = semconv.MessagingSystemKey.String("GCP pub/sub")

func NewGcpPubSub(ctx context.Context) (PubSub, error) {
	ctx, span := otel.StartSpan(
		ctx,
		"newGcpPubSub",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(msgType),
	)
	defer span.End()

	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return nil, otel.RecordOutcome(errors.New("unexpectedly missing GCP_PROJECT_ID"), span)
	}
	subClient, err := gcp_pubsub.NewSubscriberClient(ctx)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}
	pubClient, err := gcp_pubsub.NewPublisherClient(ctx)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}
	inner := &gcpPubSub{
		project:   projectID,
		subClient: subClient,
		pubClient: pubClient,
	}
	return &spannedPubSub{
		inner:   inner,
		msgType: msgType,
	}, nil
}

func (c *gcpPubSub) Ack(ctx context.Context, realm types.RealmID, tenant string, ids []string) error {
	err := c.subClient.Acknowledge(ctx, &pubsubpb.AcknowledgeRequest{
		Subscription: subscriptionName(c.project, realm, tenant),
		AckIds:       ids,
	})
	return err
}

func (c *gcpPubSub) Publish(ctx context.Context, realm types.RealmID, tenant string, event EventMessage) error {
	enc, err := json.Marshal(event)
	if err != nil {
		return types.NewHTTPError(http.StatusBadRequest, err)
	}
	pubRequest := pubsubpb.PublishRequest{
		Topic: topicName(c.project, realm, tenant),
		Messages: []*pubsubpb.PubsubMessage{{
			Data: enc,
		}},
	}
	_, err = c.pubClient.Publish(ctx, &pubRequest)
	if errorHasCode(err, codes.NotFound) {
		if err := c.createTopicAndSub(ctx, realm, tenant); err != nil {
			return err
		}
		_, err = c.pubClient.Publish(ctx, &pubRequest)
	}
	if err != nil {
		return types.NewHTTPError(http.StatusInternalServerError, err)
	}
	return nil
}

func (c *gcpPubSub) Pull(ctx context.Context, realm types.RealmID, tenant string, max uint16) ([]responses.TenantLogEntry, error) {
	resp, err := c.subClient.Pull(ctx, &pubsubpb.PullRequest{
		Subscription:      subscriptionName(c.project, realm, tenant),
		ReturnImmediately: false,
		MaxMessages:       int32(max),
	})
	if errorHasCode(err, codes.NotFound) {
		err = c.createTopicAndSub(ctx, realm, tenant)
		if err != nil {
			return nil, types.NewHTTPError(http.StatusInternalServerError, err)
		}
		return []responses.TenantLogEntry{}, nil
	}
	if err != nil {
		return nil, types.NewHTTPError(http.StatusInternalServerError, err)
	}
	results := make([]responses.TenantLogEntry, 0, len(resp.ReceivedMessages))
	for _, rm := range resp.ReceivedMessages {
		m := rm.GetMessage()
		em := EventMessage{}
		if err = json.Unmarshal(m.GetData(), &em); err != nil {
			return nil, types.NewHTTPError(http.StatusInternalServerError, err)
		}
		e := responses.TenantLogEntry{
			ID:         m.GetMessageId(),
			Ack:        rm.GetAckId(),
			When:       m.GetPublishTime().AsTime(),
			UserID:     em.User,
			Event:      em.Event,
			GuessCount: em.GuessCount,
			NumGuesses: em.NumGuesses,
		}
		results = append(results, e)
	}
	return results, nil
}

func (c *gcpPubSub) createTopicAndSub(ctx context.Context, realm types.RealmID, tenant string) error {
	ctx, span := otel.StartSpan(
		ctx,
		"CreateTopicAndSub",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(msgType),
	)
	defer span.End()

	topicName := topicName(c.project, realm, tenant)
	labels := map[string]string{"realm": realm.String(), "tenant": tenant}
	_, err := c.pubClient.CreateTopic(ctx, &pubsubpb.Topic{
		Name:   topicName,
		Labels: labels,
	})
	if err != nil && !errorHasCode(err, codes.AlreadyExists) {
		return otel.RecordOutcome(err, span)
	}

	_, err = c.subClient.CreateSubscription(ctx, &pubsubpb.Subscription{
		Name:                     subscriptionName(c.project, realm, tenant),
		Topic:                    topicName,
		AckDeadlineSeconds:       10,
		RetainAckedMessages:      false,
		MessageRetentionDuration: nil,
		Labels:                   labels,
		EnableMessageOrdering:    false,
		ExpirationPolicy: &pubsubpb.ExpirationPolicy{
			Ttl: nil,
		},
		Filter:                        "",
		DeadLetterPolicy:              nil,
		RetryPolicy:                   nil,
		Detached:                      false,
		EnableExactlyOnceDelivery:     true,
		TopicMessageRetentionDuration: nil,
		State:                         0,
	})
	if errorHasCode(err, codes.AlreadyExists) {
		err = nil
	}
	return otel.RecordOutcome(err, span)
}

func errorHasCode(err error, code codes.Code) bool {
	if err == nil {
		return false
	}
	status, ok := status.FromError(err)
	return ok && status.Code() == code
}

func topicName(project string, realm types.RealmID, tenant string) string {
	return fmt.Sprintf("projects/%s/topics/tenant-%s-%s", project, tenant, realm)
}

func subscriptionName(project string, realm types.RealmID, tenant string) string {
	return fmt.Sprintf("projects/%s/subscriptions/tenant-%s-%s-sub", project, tenant, realm)
}
