package secrets

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestParseKid(t *testing.T) {
	// Valid input
	token := &jwt.Token{
		Header: map[string]interface{}{
			"kid": "juicebox:456",
		},
	}

	tenantName, version, err := ParseKid(token)
	assert.NoError(t, err)
	expectedTenantName := "juicebox"
	expectedVersion := uint64(456)
	assert.Equal(t, expectedTenantName, *tenantName)
	assert.Equal(t, expectedVersion, *version)

	// "kid" is not a string
	token = &jwt.Token{
		Header: map[string]interface{}{"kid": 5},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid is not a string")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// "kid" must only contain alphanumeric characters
	token = &jwt.Token{
		Header: map[string]interface{}{"kid": "abc123//*:2"},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid contains non-alphanumeric tenant name")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// "kid" can also have "test-" prefix
	token = &jwt.Token{
		Header: map[string]interface{}{"kid": "test-abc123:456"},
	}

	tenantName, version, err = ParseKid(token)
	assert.NoError(t, err)
	expectedTenantName = "test-abc123"
	expectedVersion = uint64(456)
	assert.Equal(t, expectedTenantName, *tenantName)
	assert.Equal(t, expectedVersion, *version)

	// Missing "kid" field in the token header
	token = &jwt.Token{
		Header: map[string]interface{}{},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt missing kid")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// Invalid "kid" field format
	token = &jwt.Token{
		Header: map[string]interface{}{
			"kid": "invalid-format",
		},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid incorrectly formatted")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)

	// Invalid version number in the "kid" field
	token = &jwt.Token{
		Header: map[string]interface{}{
			"kid": "example123:invalid-version:whoa",
		},
	}

	tenantName, version, err = ParseKid(token)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt kid contained invalid version")
	assert.Nil(t, tenantName)
	assert.Nil(t, version)
}
