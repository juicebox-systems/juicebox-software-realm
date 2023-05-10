package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/juicebox-software-realm/types"
)

type MemorySecretsManager struct {
	secrets map[string]map[uint64][]byte
}

func NewMemorySecretsManager() (*MemorySecretsManager, error) {
	secretsJSON := os.Getenv("TENANT_SECRETS")
	if secretsJSON == "" {
		return nil, errors.New("unexpectedly missing TENANT_SECRETS")
	}

	var unmarshaledSecrets map[string]map[uint64]string
	err := json.Unmarshal([]byte(secretsJSON), &unmarshaledSecrets)
	if err != nil {
		return nil, err
	}

	secrets := make(map[string]map[uint64][]byte)

	regex := regexp.MustCompile("^[a-zA-Z0-9]+$")

	for tenantName, versionAndSecrets := range unmarshaledSecrets {
		if match := regex.MatchString(tenantName); !match {
			return nil, errors.New("tenant names must be alphanumeric")
		}
		prefixedTenantName := types.JuiceboxTenantSecretPrefix + tenantName
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

func (sm MemorySecretsManager) GetSecret(_ context.Context, name string, version uint64) ([]byte, error) {
	secretVersions, ok := sm.secrets[name]
	if !ok {
		return nil, fmt.Errorf("failed to get secret versions %s", name)
	}
	secret, ok := secretVersions[version]
	if !ok {
		return nil, fmt.Errorf("failed to get secret %s with version %d", name, version)
	}
	return secret, nil
}
