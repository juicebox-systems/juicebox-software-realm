package secrets

import (
	"context"
	"fmt"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/juicebox-software-realm/trace"
	"go.opentelemetry.io/otel/codes"
)

type GcpSecretsManager struct {
	client    *secretmanager.Client
	projectID string
}

func NewGcpSecretsManager(ctx context.Context) (*GcpSecretsManager, error) {
	ctx, span := trace.StartSpan(ctx, "NewGcpSecretsManager")
	defer span.End()

	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		err := fmt.Errorf("unexpectedly missing GCP_PROJECT_ID")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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
	ctx, span := trace.StartSpan(ctx, "GetSecret")
	defer span.End()

	result, err := sm.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%d", sm.projectID, name, version),
	})

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return result.Payload.Data, nil
}
