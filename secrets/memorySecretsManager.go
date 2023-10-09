package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/types"
)

type MemorySecretsManager struct {
	secrets map[string]map[uint64][]byte
}

func NewMemorySecretsManager(ctx context.Context) (*MemorySecretsManager, error) {
	return NewMemorySecretsManagerWithPrefix(ctx, types.JuiceboxTenantSecretPrefix)
}

func NewMemorySecretsManagerWithPrefix(ctx context.Context, secretPrefix string) (*MemorySecretsManager, error) {
	_, span := otel.StartSpan(ctx, "NewMemorySecretsManager")
	defer span.End()

	secretsJSON := os.Getenv("TENANT_SECRETS")
	if secretsJSON == "" {
		err := errors.New("unexpectedly missing TENANT_SECRETS")
		return nil, otel.RecordOutcome(err, span)
	}

	var unmarshaledSecrets map[string]map[uint64]string
	err := json.Unmarshal([]byte(secretsJSON), &unmarshaledSecrets)
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}

	secrets := make(map[string]map[uint64][]byte)

	regex := regexp.MustCompile("^(test-)?[a-zA-Z0-9]+$")

	for tenantName, versionAndSecrets := range unmarshaledSecrets {
		if match := regex.MatchString(tenantName); !match {
			err := errors.New("tenant names must be alphanumeric")
			return nil, otel.RecordOutcome(err, span)
		}
		prefixedTenantName := secretPrefix + tenantName
		for version, secret := range versionAndSecrets {
			m, ok := secrets[prefixedTenantName]
			if !ok {
				m = make(map[uint64][]byte)
			}
			m[version] = []byte(secret)
			secrets[prefixedTenantName] = m
		}
	}

	return &MemorySecretsManager{
		secrets: secrets,
	}, nil
}

func (sm MemorySecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	_, span := otel.StartSpan(ctx, "GetSecret")
	defer span.End()

	secretVersions, ok := sm.secrets[name]
	if !ok {
		err := fmt.Errorf("failed to get secret versions %s", name)
		return nil, otel.RecordOutcome(err, span)
	}
	secret, ok := secretVersions[version]
	if !ok {
		err := fmt.Errorf("failed to get secret %s with version %d", name, version)
		return nil, otel.RecordOutcome(err, span)
	}
	return secret, nil
}
