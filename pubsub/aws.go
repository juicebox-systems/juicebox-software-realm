package pubsub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

type sqsClient struct {
	client    *sqs.Client
	lock      sync.Mutex
	queueURLs map[string]string
}

func newSqsPubSub(ctx context.Context, cfg aws.Config) (PubSub, attribute.KeyValue, error) {
	msgType := semconv.MessagingSystemKey.String("SQS")
	_, span := otel.StartSpan(
		ctx,
		"newSqsPubSub",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(msgType),
	)
	defer span.End()

	client := sqs.NewFromConfig(cfg)
	return &sqsClient{
		client:    client,
		queueURLs: make(map[string]string),
	}, msgType, nil
}

func (s *sqsClient) Ack(ctx context.Context, realmID types.RealmID, tenant string, ids []string) error {
	queueURL, err := s.queueURL(ctx, realmID, tenant)
	if err != nil {
		return err
	}
	entries := make([]sqsTypes.DeleteMessageBatchRequestEntry, len(ids))
	for index := range ids {
		entryID := fmt.Sprintf("%d", index)
		entries[index] = sqsTypes.DeleteMessageBatchRequestEntry{
			Id:            &entryID,
			ReceiptHandle: &ids[index],
		}
	}
	res, err := s.client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{
		Entries:  entries,
		QueueUrl: &queueURL,
	})
	if err != nil {
		return err
	}
	if len(res.Failed) > 0 {
		return types.NewHTTPError(http.StatusBadRequest, fmt.Errorf("%d ack ids were invalid", len(res.Failed)))
	}
	return nil
}

func (s *sqsClient) Publish(ctx context.Context, realmID types.RealmID, tenant string, event EventMessage) error {
	queueURL, err := s.queueURL(ctx, realmID, tenant)
	if err != nil {
		return err
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	bodyStr := string(body)
	_, err = s.client.SendMessage(ctx, &sqs.SendMessageInput{
		MessageBody:  &bodyStr,
		QueueUrl:     &queueURL,
		DelaySeconds: 0,
	})
	return err
}

func (s *sqsClient) Pull(ctx context.Context, realmID types.RealmID, tenant string, maxRows uint16) ([]responses.TenantLogEntry, error) {
	queueURL, err := s.queueURL(ctx, realmID, tenant)
	if err != nil {
		return nil, err
	}

	msgs, err := s.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            &queueURL,
		VisibilityTimeout:   10,
		MaxNumberOfMessages: int32(min(maxRows, 10)),
		AttributeNames:      []sqsTypes.QueueAttributeName{sqsTypes.QueueAttributeNameAll},
		WaitTimeSeconds:     20,
	})
	if err != nil {
		return nil, types.NewHTTPError(http.StatusInternalServerError, err)
	}
	results := make([]responses.TenantLogEntry, 0, len(msgs.Messages))
	for _, msg := range msgs.Messages {
		em := EventMessage{}
		if err = json.Unmarshal([]byte(*msg.Body), &em); err != nil {
			return nil, types.NewHTTPError(http.StatusInternalServerError, err)
		}
		sentMillis, err := strconv.ParseInt(msg.Attributes["SentTimestamp"], 10, 64)
		if err != nil {
			return nil, types.NewHTTPError(http.StatusInternalServerError, err)
		}
		e := responses.TenantLogEntry{
			ID:         *msg.MessageId,
			Ack:        *msg.ReceiptHandle,
			When:       time.UnixMilli(sentMillis),
			UserID:     em.User,
			Event:      em.Event,
			GuessCount: em.GuessCount,
			NumGuesses: em.NumGuesses,
		}
		results = append(results, e)
	}
	return results, nil
}

func (s *sqsClient) queueURL(ctx context.Context, realmID types.RealmID, tenant string) (string, error) {
	qn := fmt.Sprintf("tenant-%s-%s", tenant, realmID)
	cached, ok := s.cachedQueueURL(qn)
	if ok {
		return cached, nil
	}
	url, err := s.client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: &qn})
	if err != nil {
		var qne *sqsTypes.QueueDoesNotExist
		if errors.As(err, &qne) {
			res, err := s.client.CreateQueue(ctx, &sqs.CreateQueueInput{
				QueueName: &qn,
				Attributes: map[string]string{
					"MessageRetentionPeriod": strconv.Itoa(7 * 24 * 60 * 60),
				},
				Tags: map[string]string{
					"Realm":  realmID.String(),
					"Tenant": tenant,
				},
			})
			if err != nil {
				return "", err
			}
			s.addQueueURL(qn, *url.QueueUrl)
			return *res.QueueUrl, nil
		}
		return "", err
	}
	s.addQueueURL(qn, *url.QueueUrl)
	return *url.QueueUrl, nil
}

func (s *sqsClient) cachedQueueURL(qn string) (string, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	cached, ok := s.queueURLs[qn]
	return cached, ok
}

func (s *sqsClient) addQueueURL(qn string, url string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.queueURLs[qn] = url
}
