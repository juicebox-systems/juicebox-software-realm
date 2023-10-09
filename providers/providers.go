package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/pubsub"
	"github.com/juicebox-systems/juicebox-software-realm/records"
	"github.com/juicebox-systems/juicebox-software-realm/secrets"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/codes"
)

// Provider represents a generic interface into the
// record and secrets storage of your choice
type Provider struct {
	Name           types.ProviderName
	RecordStore    records.RecordStore
	SecretsManager secrets.SecretsManager
	PubSub         pubsub.PubSub
}

func Parse(nameString string) (types.ProviderName, error) {
	switch strings.ToLower(nameString) {
	case "gcp":
		return types.GCP, nil
	case "aws":
		return types.AWS, nil
	case "mongo":
		return types.Mongo, nil
	case "memory":
		return types.Memory, nil
	default:
		return -1, fmt.Errorf("invalid ProviderName: %s", nameString)
	}
}

func NewProvider(ctx context.Context, name types.ProviderName, realmID types.RealmID) (*Provider, error) {
	ctx, span := otel.StartSpan(ctx, "NewProvider")
	defer span.End()

	fmt.Printf("Realm ID: %s\n\n", realmID.String())

	fmt.Print("Connecting to secrets manager...")

	secretsManager, err := secrets.NewSecretsManager(ctx, name, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to secrets manager: %s.\n", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	fmt.Print("\rEstablished connection to secrets manager.\n")

	fmt.Print("Connecting to record store...")

	recordStore, err := records.NewRecordStore(ctx, name, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to record store: %s.\n", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	fmt.Print("\rEstablished connection to record store.\n")

	fmt.Print("Connecting to pub/sub...")
	pubsub, err := pubsub.NewPubSub(ctx, name, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to pubsub system: %s.\n", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	fmt.Print("\rEstablished connection to pub/sub system.\n\n")

	return &Provider{
		Name:           name,
		RecordStore:    recordStore,
		SecretsManager: secretsManager,
		PubSub:         pubsub,
	}, nil
}
