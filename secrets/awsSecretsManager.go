package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/juicebox-software-realm/otel"
	"go.opentelemetry.io/otel/codes"
)

type AwsSecretsManager struct {
	svc *secretsmanager.SecretsManager
}

func NewAwsSecretsManager(ctx context.Context) (*AwsSecretsManager, error) {
	_, span := otel.StartSpan(ctx, "NewAwsSecretsManager")
	defer span.End()

	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		err := errors.New("unexpectedly missing AWS_REGION_NAME")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	session, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	svc := secretsmanager.New(session)

	return &AwsSecretsManager{
		svc: svc,
	}, nil
}

func (sm AwsSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	ctx, span := otel.StartSpan(ctx, "GetSecret")
	defer span.End()

	versionString := fmt.Sprint(version)

	input := secretsmanager.GetSecretValueInput{
		SecretId:     &name,
		VersionStage: &versionString,
	}

	result, err := sm.svc.GetSecretValueWithContext(ctx, &input)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if len(result.SecretBinary) > 0 {
		return result.SecretBinary, nil
	}

	return []byte(*result.SecretString), nil
}
