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

func NewProvider(name types.ProviderName, realmId uuid.UUID) (*Provider, error) {
	fmt.Printf("Realm Id: %s\n\n", realmId.String())

	fmt.Print("Connecting to secrets manager...")

	secretsManager, error := secrets.NewSecretsManager(name, realmId)
	if error != nil {
		fmt.Printf("\rFailed to connect to secrets manager: %s.\n", error)
		return nil, error
	}

	fmt.Print("\rEstablished connection to secrets manager.\n")

	fmt.Print("Connecting to record store...")

	recordStore, error := records.NewRecordStore(name, realmId)
	if error != nil {
		fmt.Printf("\rFailed to connect to record store: %s.\n", error)
		return nil, error
	}

	fmt.Print("\rEstablished connection to record store.\n\n")

	return &Provider{
		Name:           name,
		RecordStore:    recordStore,
		SecretsManager: secretsManager,
	}, nil
}
