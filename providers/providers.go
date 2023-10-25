package providers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/pubsub"
	"github.com/juicebox-systems/juicebox-software-realm/records"
	"github.com/juicebox-systems/juicebox-software-realm/secrets"
	"github.com/juicebox-systems/juicebox-software-realm/types"
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

	options, err := newOptions(ctx, name)
	if err != nil {
		fmt.Printf("Failed to configure provider: %s\n", err)
		return nil, otel.RecordOutcome(err, span)
	}

	fmt.Print("Connecting to secrets manager...")

	secretsManager, err := secrets.NewSecretsManager(ctx, name, *options, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to secrets manager: %s.\n", err)
		return nil, otel.RecordOutcome(err, span)
	}

	fmt.Print("\rEstablished connection to secrets manager.\n")

	fmt.Print("Connecting to record store...")

	recordStore, err := records.NewRecordStore(ctx, name, *options, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to record store: %s.\n", err)
		return nil, otel.RecordOutcome(err, span)
	}

	fmt.Print("\rEstablished connection to record store.\n")

	fmt.Print("Connecting to pub/sub...")
	pubsub, err := pubsub.NewPubSub(ctx, name, *options, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to pubsub system: %s.\n", err)
		return nil, otel.RecordOutcome(err, span)
	}
	fmt.Print("\rEstablished connection to pub/sub system.\n\n")

	return &Provider{
		Name:           name,
		RecordStore:    recordStore,
		SecretsManager: secretsManager,
		PubSub:         pubsub,
	}, nil
}

func newOptions(ctx context.Context, name types.ProviderName) (*types.ProviderOptions, error) {
	if name == types.AWS {
		return newAwsOptions(ctx)
	}
	return &types.ProviderOptions{}, nil
}

func newAwsOptions(ctx context.Context) (*types.ProviderOptions, error) {
	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		return nil, errors.New("unexpectedly missing AWS_REGION_NAME")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	cfg.ClientLogMode |= aws.LogRetries
	return &types.ProviderOptions{Config: cfg}, nil
}
