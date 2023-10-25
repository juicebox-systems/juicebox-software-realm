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

	fmt.Print("Connecting to secrets manager...")

	c, err := constructor(ctx, name)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	secretsManager, err := c.NewSecretsManager(ctx, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to secrets manager: %s.\n", err)
		return nil, otel.RecordOutcome(err, span)
	}

	fmt.Print("\rEstablished connection to secrets manager.\n")

	fmt.Print("Connecting to record store...")

	recordStore, err := c.NewRecordStore(ctx, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to record store: %s.\n", err)
		return nil, otel.RecordOutcome(err, span)
	}

	fmt.Print("\rEstablished connection to record store.\n")

	fmt.Print("Connecting to pub/sub...")
	pubsub, err := c.NewPubSub(ctx, realmID)
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

func constructor(ctx context.Context, n types.ProviderName) (providerConstructor, error) {
	switch n {
	case types.GCP:
		return &gcpProviderConstructor{}, nil
	case types.AWS:
		return newAwsProviderConstructor(ctx)
	case types.Mongo:
		return &mongoProviderConstructor{}, nil
	case types.Memory:
		return &memoryProviderConstructor{}, nil
	default:
		return nil, fmt.Errorf("unexpected ProviderName of %v", n)
	}
}

type providerConstructor interface {
	NewSecretsManager(ctx context.Context, realm types.RealmID) (secrets.SecretsManager, error)
	NewRecordStore(ctx context.Context, realm types.RealmID) (records.RecordStore, error)
	NewPubSub(ctx context.Context, realm types.RealmID) (pubsub.PubSub, error)
}

type awsProviderConstructor struct {
	config aws.Config
}

func newAwsProviderConstructor(ctx context.Context) (providerConstructor, error) {
	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		return nil, errors.New("unexpectedly missing AWS_REGION_NAME")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	cfg.ClientLogMode |= aws.LogRetries
	return &awsProviderConstructor{config: cfg}, nil
}

func (a *awsProviderConstructor) NewSecretsManager(ctx context.Context, _ types.RealmID) (secrets.SecretsManager, error) {
	return secrets.NewAwsSecretsManager(ctx, a.config)
}

func (a *awsProviderConstructor) NewRecordStore(ctx context.Context, realm types.RealmID) (records.RecordStore, error) {
	return records.NewDynamoDbRecordStore(ctx, a.config, realm)
}

func (a *awsProviderConstructor) NewPubSub(ctx context.Context, _ types.RealmID) (pubsub.PubSub, error) {
	return pubsub.NewSqsPubSub(ctx, a.config)
}

type gcpProviderConstructor struct{}

func (g *gcpProviderConstructor) NewSecretsManager(ctx context.Context, _ types.RealmID) (secrets.SecretsManager, error) {
	return secrets.NewGcpSecretsManager(ctx)
}

func (g *gcpProviderConstructor) NewRecordStore(ctx context.Context, realm types.RealmID) (records.RecordStore, error) {
	return records.NewBigtableRecordStore(ctx, realm)
}

func (g *gcpProviderConstructor) NewPubSub(ctx context.Context, _ types.RealmID) (pubsub.PubSub, error) {
	return pubsub.NewGcpPubSub(ctx)
}

type mongoProviderConstructor struct{}

func (c *mongoProviderConstructor) NewSecretsManager(ctx context.Context, realm types.RealmID) (secrets.SecretsManager, error) {
	return secrets.NewMongoSecretsManager(ctx, realm)
}

func (c *mongoProviderConstructor) NewRecordStore(ctx context.Context, realm types.RealmID) (records.RecordStore, error) {
	return records.NewMongoRecordStore(ctx, realm)
}

func (c *mongoProviderConstructor) NewPubSub(ctx context.Context, realm types.RealmID) (pubsub.PubSub, error) {
	return pubsub.NewMongoPubSub(ctx, realm)
}

type memoryProviderConstructor struct{}

func (c *memoryProviderConstructor) NewSecretsManager(ctx context.Context, _ types.RealmID) (secrets.SecretsManager, error) {
	return secrets.NewMemorySecretsManager(ctx)
}

func (c *memoryProviderConstructor) NewRecordStore(_ context.Context, _ types.RealmID) (records.RecordStore, error) {
	return records.NewMemoryRecordStore(), nil
}

func (c *memoryProviderConstructor) NewPubSub(_ context.Context, _ types.RealmID) (pubsub.PubSub, error) {
	return pubsub.NewMemPubSub(), nil
}
