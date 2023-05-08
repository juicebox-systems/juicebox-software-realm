package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-jwt/jwt/v4"
)

type GcpSecretsManager struct {
	client    *secretmanager.Client
	projectID string
}

func NewGcpSecretsManager() (*GcpSecretsManager, error) {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return nil, fmt.Errorf("unexpectedly missing GCP_PROJECT_ID")
	}

	client, err := secretmanager.NewClient(context.Background())
	if err != nil {
		return nil, err
	}

	return &GcpSecretsManager{
		client:    client,
		projectID: projectID,
	}, nil
}

func (sm GcpSecretsManager) Close() {
	sm.client.Close()
}

func (sm GcpSecretsManager) GetSecret(name string, version uint64) ([]byte, error) {
	result, err := sm.client.AccessSecretVersion(context.Background(), &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%d", sm.projectID, name, version),
	})

	if err != nil {
		return nil, err
	}

	return result.Payload.Data, nil
}

func (sm GcpSecretsManager) GetJWTSigningKey(token *jwt.Token) (interface{}, error) {
	name, version, err := ParseKid(token)
	if err != nil {
		return nil, err
	}

	key, err := sm.GetSecret(*name, *version)
	if err != nil {
		return nil, errors.New("no signing key for jwt")
	}

	return key, nil
}
