package secrets

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

var ParseKid = parseKid

func TestParseKid(t *testing.T) {
	// Valid input
	token := &jwt.Token{
		Header: map[string]interface{}{
			"kid": "juicebox:456",
		},
	}

	tenantSecretsKey, version, err := ParseKid(token)
	assert.NoError(t, err)
	expectedTenantSecretsKey := types.JuiceboxTenantSecretPrefix + "juicebox"
	expectedVersion := uint64(456)
	assert.Equal(t, expectedTenantSecretsKey, *tenantSecretsKey)
	assert.Equal(t, expectedVersion, *version)

	// "kid" is not a string
	token = &jwt.Token{
		Header: map[string]interface{}{"kid": 5},
	}

	tenantSecretsKey, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid is not a string")
	assert.Nil(t, tenantSecretsKey)
	assert.Nil(t, version)

	// Missing "kid" field in the token header
	token = &jwt.Token{
		Header: map[string]interface{}{},
	}

	tenantSecretsKey, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt missing kid")
	assert.Nil(t, tenantSecretsKey)
	assert.Nil(t, version)

	// Invalid "kid" field format
	token = &jwt.Token{
		Header: map[string]interface{}{
			"kid": "invalid-format",
		},
	}

	tenantSecretsKey, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid incorrectly formatted")
	assert.Nil(t, tenantSecretsKey)
	assert.Nil(t, version)

	// Invalid version number in the "kid" field
	token = &jwt.Token{
		Header: map[string]interface{}{
			"kid": "example-123:invalid-version:whoa",
		},
	}

	tenantSecretsKey, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid contained invalid version")
	assert.Nil(t, tenantSecretsKey)
	assert.Nil(t, version)
}
