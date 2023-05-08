package secrets

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type MemorySecretsManager struct{}

var memorySecrets = map[string]map[uint64][]byte{"tenant-test": {1: []byte("an-auth-token-key")}}

func (sm MemorySecretsManager) GetSecret(name string, version uint64) ([]byte, error) {
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

func (sm MemorySecretsManager) GetJWTSigningKey(token *jwt.Token) (interface{}, error) {
	name, version, err := ParseKid(token)
	if err != nil {
		return nil, err
	}

	key, err := sm.GetSecret(*name, *version)
	if err != nil {
		return nil, errors.New("no signing key for jwt")
	}

	return key, nil
}
