package secrets

import (
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/golang-jwt/jwt"
)

type AwsSecretsManager struct {
	svc *secretsmanager.SecretsManager
}

func NewAwsSecretsManager() (*AwsSecretsManager, error) {
	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		return nil, errors.New("unexpectedly missing AWS_REGION_NAME")
	}

	session, error := session.NewSession(&aws.Config{
		Region: &region,
	})
	if error != nil {
		return nil, error
	}

	svc := secretsmanager.New(session)

	return &AwsSecretsManager{
		svc: svc,
	}, nil
}

func (sm AwsSecretsManager) GetSecret(name string, version uint64) ([]byte, error) {
	versionString := fmt.Sprintf("%d", version)

	input := secretsmanager.GetSecretValueInput{
		SecretId:     &name,
		VersionStage: &versionString,
	}

	result, error := sm.svc.GetSecretValue(&input)
	if error != nil {
		return nil, error
	}

	if len(result.SecretBinary) > 0 {
		return result.SecretBinary, nil
	}

	return []byte(*result.SecretString), nil
}

func (sm AwsSecretsManager) GetJWTSigningKey(token *jwt.Token) (interface{}, error) {
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
