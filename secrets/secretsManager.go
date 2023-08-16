package secrets

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-software-realm/otel"
	"github.com/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/codes"
)

// SecretsManager represents a generic interface into the
// secrets provider of your choice.
type SecretsManager interface {
	GetSecret(ctx context.Context, name string, version uint64) ([]byte, error)
}

func GetJWTSigningKey(ctx context.Context, sm SecretsManager, token *jwt.Token) ([]byte, error) {
	name, version, err := ParseKid(token)
	if err != nil {
		return nil, err
	}

	tenantSecretKey := types.JuiceboxTenantSecretPrefix + *name

	key, err := sm.GetSecret(ctx, tenantSecretKey, *version)
	if err != nil {
		return nil, errors.New("no signing key for jwt")
	}

	return key, nil
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

	if match, err := regexp.MatchString("^(test-)?[a-zA-Z0-9]+$", tenantName); !match || err != nil {
		return nil, nil, errors.New("jwt kid contains non-alphanumeric tenant name")
	}

	versionString := split[1]
	version, err := strconv.ParseUint(versionString, 10, 64)
	if err != nil {
		return nil, nil, errors.New("jwt kid contained invalid version")
	}

	return &tenantName, &version, nil
}

func NewSecretsManager(ctx context.Context, provider types.ProviderName, realmID types.RealmID) (SecretsManager, error) {
	ctx, span := otel.StartSpan(ctx, "NewSecretsManager")
	defer span.End()

	switch provider {
	case types.GCP:
		return NewGcpSecretsManager(ctx)
	case types.Memory:
		return NewMemorySecretsManager(ctx)
	case types.AWS:
		return NewAwsSecretsManager(ctx)
	case types.Mongo:
		return NewMongoSecretsManager(ctx, realmID)
	}

	err := fmt.Errorf("unexpected provider %v", provider)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	return nil, err
}
