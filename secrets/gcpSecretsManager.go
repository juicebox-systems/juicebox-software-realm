package secrets

import (
	"context"
	"fmt"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
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

func (sm GcpSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	result, err := sm.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%d", sm.projectID, name, version),
	})

	if err != nil {
		return nil, err
	}

	return result.Payload.Data, nil
}
