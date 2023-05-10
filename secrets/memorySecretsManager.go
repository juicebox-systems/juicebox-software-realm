package secrets

import (
	"context"
	"fmt"
)

type MemorySecretsManager struct{}

var memorySecrets = map[string]map[uint64][]byte{"jb-sw-tenant-test": {1: []byte("an-auth-token-key")}}

func (sm MemorySecretsManager) GetSecret(_ context.Context, name string, version uint64) ([]byte, error) {
	secretVersions, ok := memorySecrets[name]
	if !ok {
		return nil, fmt.Errorf("failed to get secret versions %s", name)
	}
	secret, ok := secretVersions[version]
	if !ok {
		return nil, fmt.Errorf("failed to get secret %s with version %d", name, version)
	}
	return secret, nil
}
