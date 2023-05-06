package secrets

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/juicebox-software-realm/types"
)

type SecretsManager interface {
	GetSecret(name string, version uint64) ([]byte, error)
	GetJWTSigningKey(token *jwt.Token) (interface{}, error)
}

func keyFunc(t *jwt.Token) (interface{}, error) {
	return []byte("your-secret-key"), nil
}

func ParseKid(token *jwt.Token) (*string, *uint64, error) {
	kid, ok := token.Header["kid"]
	if !ok {
		return nil, nil, errors.New("jwt missing kid")
	}

	keyAndVersion, ok := kid.(string)
	if !ok {
		return nil, nil, errors.New("jwt kid is not a string")
	}

	split := strings.SplitN(keyAndVersion, ":", 2)
	if len(split) != 2 {
		return nil, nil, errors.New("jwt kid incorrectly formatted")
	}

	tenantName := split[0]
	tenantSecretsKey := "tenant-" + tenantName

	versionString := split[1]
	version, error := strconv.ParseUint(versionString, 10, 64)
	if error != nil {
		return nil, nil, errors.New("jwt kid contained invalid version")
	}

	return &tenantSecretsKey, &version, nil
}

func NewSecretsManager(provider types.ProviderName) (SecretsManager, error) {
	switch provider {
	case types.GCP:
		return NewGcpSecretsManager()
	case types.Memory:
		return MemorySecretsManager{}, nil
	case types.AWS:
		return nil, errors.New("aws not yet supported")
	}
	return nil, fmt.Errorf("Unexpected provider %v", provider)
}
