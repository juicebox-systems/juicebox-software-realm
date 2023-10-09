package pubsub

import (
	"context"
	"fmt"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type PubSub interface {
	Ack(ctx context.Context, realm types.RealmID, tenant string, ids []string) error
	Publish(ctx context.Context, realm types.RealmID, tenant string, event EventMessage) error
	// If there are no pending messages, implementations of Pull may choose to
	// wait a reasonable (~30 seconds) amount of time to see if a new message
	// turns up.
	Pull(ctx context.Context, realm types.RealmID, tenant string, maxRows uint16) ([]responses.TenantLogEntry, error)
}

func NewPubSub(ctx context.Context, provider types.ProviderName, realmID types.RealmID) (PubSub, error) {
	ctx, span := otel.StartSpan(ctx, "NewPubSub")
	defer span.End()

	var ps PubSub
	var err error
	var msgType attribute.KeyValue
	switch provider {
	case types.GCP:
		ps, msgType, err = newGcpPubSub(ctx)
	case types.Memory:
		ps, msgType = newMemPubSub()
	case types.AWS:
		ps, msgType, err = newSqsPubSub(ctx)
	case types.Mongo:
		ps, msgType, err = newMongoPubSub(ctx, realmID)
	default:
		err = fmt.Errorf("unexpected provider %v", provider)
	}
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}
	return &spannedPubSub{inner: ps, msgType: msgType}, nil
}

type EventMessage struct {
	User       string  `json:"user"`
	Event      string  `json:"event"`
	NumGuesses *uint16 `json:"num_guesses,omitempty"`
	GuessCount *uint16 `json:"guess_count,omitempty"`
}

type spannedPubSub struct {
	inner   PubSub
	msgType attribute.KeyValue
}

func (s *spannedPubSub) Ack(ctx context.Context, realm types.RealmID, tenant string, ids []string) error {
	ctx, span := s.startSpan(ctx, "Ack")
	defer span.End()

	err := s.inner.Ack(ctx, realm, tenant, ids)
	return otel.RecordOutcome(err, span)
}

func (s *spannedPubSub) Publish(ctx context.Context, realm types.RealmID, tenant string, event EventMessage) error {
	ctx, span := s.startSpan(ctx, "Publish")
	defer span.End()

	err := s.inner.Publish(ctx, realm, tenant, event)
	return otel.RecordOutcome(err, span)
}

func (s *spannedPubSub) Pull(ctx context.Context, realm types.RealmID, tenant string, maxRows uint16) ([]responses.TenantLogEntry, error) {
	ctx, span := s.startSpan(ctx, "Pull")
	defer span.End()

	events, err := s.inner.Pull(ctx, realm, tenant, maxRows)
	return events, otel.RecordOutcome(err, span)
}

func (s *spannedPubSub) startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	ctx, span := otel.StartSpan(
		ctx,
		name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(s.msgType),
	)
	return ctx, span
}
