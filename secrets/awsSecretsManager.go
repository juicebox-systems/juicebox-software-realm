package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
)

type AwsSecretsManager struct {
	svc *secretsmanager.Client
}

func NewAwsSecretsManager(ctx context.Context, cfg aws.Config) (SecretsManager, error) {
	_, span := otel.StartSpan(ctx, "NewAwsSecretsManager")
	defer span.End()

	return newCachingSecretsManager(&AwsSecretsManager{
		svc: secretsmanager.NewFromConfig(cfg),
	}), nil
}

func (sm *AwsSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	ctx, span := otel.StartSpan(ctx, "GetSecret")
	defer span.End()

	versionString := fmt.Sprint(version)

	input := secretsmanager.GetSecretValueInput{
		SecretId:     &name,
		VersionStage: &versionString,
	}

	result, err := sm.svc.GetSecretValue(ctx, &input)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	if len(result.SecretBinary) > 0 {
		return result.SecretBinary, nil
	}

	return []byte(*result.SecretString), nil
}
