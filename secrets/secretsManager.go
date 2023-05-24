package secrets

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/juicebox-software-realm/trace"
	"github.com/juicebox-software-realm/types"
	"go.opentelemetry.io/otel/codes"
)

// SecretsManager represents a generic interface into the
// secrets provider of your choice.
type SecretsManager interface {
	GetSecret(ctx context.Context, name string, version uint64) ([]byte, error)
}

func GetJWTSigningKey(ctx context.Context, sm SecretsManager, token *jwt.Token) ([]byte, error) {
	name, version, err := parseKid(token)
	if err != nil {
		return nil, err
	}

	key, err := sm.GetSecret(ctx, *name, *version)
	if err != nil {
		return nil, errors.New("no signing key for jwt")
	}

	return key, nil
}

func parseKid(token *jwt.Token) (*string, *uint64, error) {
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

	tenantSecretsKey := types.JuiceboxTenantSecretPrefix + tenantName

	versionString := split[1]
	version, err := strconv.ParseUint(versionString, 10, 64)
	if err != nil {
		return nil, nil, errors.New("jwt kid contained invalid version")
	}

	return &tenantSecretsKey, &version, nil
}

func NewSecretsManager(ctx context.Context, provider types.ProviderName, realmID uuid.UUID) (SecretsManager, error) {
	ctx, span := trace.StartSpan(ctx, "NewSecretsManager")
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
