package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-jwt/jwt"
)

type GcpSecretsManager struct {
	client    *secretmanager.Client
	projectId string
}

func NewGcpSecretsManager() (*GcpSecretsManager, error) {
	projectId := os.Getenv("GCP_PROJECT_ID")
	if projectId == "" {
		return nil, fmt.Errorf("Unexpectedly missing GCP_PROJECT_ID")
	}

	client, error := secretmanager.NewClient(context.Background())
	if error != nil {
		return nil, error
	}

	return &GcpSecretsManager{
		client:    client,
		projectId: projectId,
	}, nil
}

func (sm GcpSecretsManager) Close() {
	sm.client.Close()
}

func (sm GcpSecretsManager) GetSecret(name string, version uint64) ([]byte, error) {
	result, error := sm.client.AccessSecretVersion(context.Background(), &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%d", sm.projectId, name, version),
	})

	if error != nil {
		return nil, error
	}

	return result.Payload.Data, nil
}

func (sm GcpSecretsManager) GetJWTSigningKey(token *jwt.Token) (interface{}, error) {
	name, version, error := ParseKid(token)
	if error != nil {
		return nil, error
	}

	key, error := sm.GetSecret(*name, *version)
	if error != nil {
		return nil, errors.New("no signing key for jwt")
	}

	return key, nil
}
