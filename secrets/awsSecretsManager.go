package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type AwsSecretsManager struct {
	svc *secretsmanager.SecretsManager
}

func NewAwsSecretsManager() (*AwsSecretsManager, error) {
	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		return nil, errors.New("unexpectedly missing AWS_REGION_NAME")
	}

	session, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		return nil, err
	}

	svc := secretsmanager.New(session)

	return &AwsSecretsManager{
		svc: svc,
	}, nil
}

func (sm AwsSecretsManager) GetSecret(_ context.Context, name string, version uint64) ([]byte, error) {
	versionString := fmt.Sprintf("%d", version)

	input := secretsmanager.GetSecretValueInput{
		SecretId:     &name,
		VersionStage: &versionString,
	}

	result, err := sm.svc.GetSecretValue(&input)
	if err != nil {
		return nil, err
	}

	if len(result.SecretBinary) > 0 {
		return result.SecretBinary, nil
	}

	return []byte(*result.SecretString), nil
}
