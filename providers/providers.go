package providers

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/juicebox-software-realm/records"
	"github.com/juicebox-software-realm/secrets"
	"github.com/juicebox-software-realm/types"
)

type Provider struct {
	Name           types.ProviderName
	RecordStore    records.RecordStore
	SecretsManager secrets.SecretsManager
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
		return "", fmt.Errorf("invalid ProviderName: %s", nameString)
	}
}

func NewProvider(name types.ProviderName, realmID uuid.UUID) (*Provider, error) {
	fmt.Printf("Realm ID: %s\n\n", realmID.String())

	fmt.Print("Connecting to secrets manager...")

	secretsManager, err := secrets.NewSecretsManager(name, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to secrets manager: %s.\n", err)
		return nil, err
	}

	fmt.Print("\rEstablished connection to secrets manager.\n")

	fmt.Print("Connecting to record store...")

	recordStore, err := records.NewRecordStore(name, realmID)
	if err != nil {
		fmt.Printf("\rFailed to connect to record store: %s.\n", err)
		return nil, err
	}

	fmt.Print("\rEstablished connection to record store.\n\n")

	return &Provider{
		Name:           name,
		RecordStore:    recordStore,
		SecretsManager: secretsManager,
	}, nil
}
