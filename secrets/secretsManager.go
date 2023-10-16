package secrets

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/types"
)

// SecretsManager represents a generic interface into the
// secrets provider of your choice.
type SecretsManager interface {
	GetSecret(ctx context.Context, name string, version uint64) ([]byte, error)
}

func GetJWTSigningKey(ctx context.Context, sm SecretsManager, token *jwt.Token) ([]byte, error) {
	return GetJWTSigningKeyWithPrefix(ctx, sm, types.JuiceboxTenantSecretPrefix, token)
}

func GetJWTSigningKeyWithPrefix(ctx context.Context, sm SecretsManager, prefix string, token *jwt.Token) ([]byte, error) {
	name, version, err := ParseKid(token)
	if err != nil {
		return nil, err
	}

	tenantSecretKey := prefix + *name

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

	var err error
	var sm SecretsManager
	switch provider {
	case types.GCP:
		sm, err = NewGcpSecretsManager(ctx)
	case types.Memory:
		sm, err = NewMemorySecretsManager(ctx)
	case types.AWS:
		sm, err = NewAwsSecretsManager(ctx)
	case types.Mongo:
		sm, err = NewMongoSecretsManager(ctx, realmID)
	default:
		err = fmt.Errorf("unexpected provider %v", provider)
	}
	if err != nil {
		return nil, otel.RecordOutcome(err, span)
	}
	return newCachingSecretsManager(sm), nil
}

type cachingSecretsManager struct {
	inner SecretsManager
	lock  sync.Mutex
	cache map[cacheKey][]byte
}

func newCachingSecretsManager(inner SecretsManager) SecretsManager {
	return &cachingSecretsManager{
		inner: inner,
		cache: make(map[cacheKey][]byte),
	}
}

func (c *cachingSecretsManager) GetSecret(ctx context.Context, name string, version uint64) ([]byte, error) {
	key := cacheKey{
		name:    name,
		version: version,
	}
	secret, ok := c.getCached(key)
	if ok {
		return secret, nil
	}
	secret, err := c.inner.GetSecret(ctx, name, version)
	if err != nil {
		return nil, err
	}
	c.addToCache(key, secret)
	return secret, nil
}

func (c *cachingSecretsManager) addToCache(key cacheKey, secret []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()
	_, exists := c.cache[key]
	c.cache[key] = secret
	if !exists {
		go func() {
			time.Sleep(time.Second * 60 * 60)
			c.expire(key)
		}()
	}
}

func (c *cachingSecretsManager) getCached(k cacheKey) ([]byte, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	secret, ok := c.cache[k]
	return secret, ok
}

func (c *cachingSecretsManager) expire(key cacheKey) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.cache, key)
}

type cacheKey struct {
	name    string
	version uint64
}
