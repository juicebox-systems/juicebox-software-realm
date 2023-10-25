package secrets

import (
	"context"
	"fmt"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
)

type GcpSecretsManager struct {
	client    *secretmanager.Client
	projectID string
}

func NewGcpSecretsManager(ctx context.Context) (SecretsManager, error) {
	ctx, span := otel.StartSpan(ctx, "NewGcpSecretsManager")
	defer span.End()

	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		err := fmt.Errorf("unexpectedly missing GCP_PROJECT_ID")
		return nil, otel.RecordOutcome(err, span)
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	return newCachingSecretsManager(&GcpSecretsManager{
		client:    client,
		projectID: projectID,
	}), nil
}

func (sm *GcpSecretsManager) Close() {
	sm.client.Close()
}

func (sm *GcpSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	ctx, span := otel.StartSpan(ctx, "GetSecret")
	defer span.End()

	result, err := sm.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%d", sm.projectID, name, version),
	})

	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	return result.Payload.Data, nil
}
