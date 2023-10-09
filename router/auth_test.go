package router

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/records"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

var UserRecordID = userRecordID

func TestUserRecordID(t *testing.T) {
	// Create a mock user token
	realmID := types.RealmID(makeRepeatingByteArray(0xFF, 16))
	header := map[string]interface{}{
		"kid": "apollo:1",
	}
	token := &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}

	// Create a mock Echo context with the user token
	e := echo.New()
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	userRecordID, verifiedClaims, err := UserRecordID(c, realmID)

	expectedUserRecordID := records.UserRecordID("1033250bfb2d27fd2a7fccba346851d517700a3ea5155429d5b5845875db75d3")
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecordID, *userRecordID)
	assert.Equal(t, token.Claims, verifiedClaims)

	// If there's a token error, shouldn't get a recordID
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeAudit,
		},
	}
	c.Set("user", token)
	userRecordID, verifiedClaims, err = UserRecordID(c, realmID)
	assert.EqualError(t, err, "jwt claims 'scope' missing user scope")
	assert.Nil(t, userRecordID)
	assert.Nil(t, verifiedClaims)
}

func TestVerifyToken(t *testing.T) {
	// Create a mock user token
	realmID := types.RealmID(makeRepeatingByteArray(0xFF, 16))
	header := map[string]interface{}{
		"kid": "apollo:1",
	}
	token := &jwt.Token{
		Header: header,
		Claims: &claims{
			jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			"audit",
		},
	}

	// Create a mock Echo context with the user token
	e := echo.New()
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	// Test when the user is not a jwt token
	c.Set("user", "not a jwt token")
	verifiedClaims, err := verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "user is not a jwt token")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt claims are of unexpected type
	invalidToken := &jwt.Token{
		Header: header,
		Claims: &jwt.RegisteredClaims{},
	}
	c.Set("user", invalidToken)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt claims of unexpected type")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt claims missing 'sub' field
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt claims missing 'sub' field")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt claims missing 'iss' field
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt claims missing 'iss' field")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt signer does not match the 'iss' field
	header["kid"] = "artemis:1"
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt 'iss' field does not match signer")
	assert.Nil(t, verifiedClaims)

	// Test when the header kid is invalid
	header["kid"] = "apollo"
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt kid incorrectly formatted")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt claims has wrong realmID in 'aud' field
	header["kid"] = "apollo:1"
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}
	expectedRealmID := types.RealmID(makeRepeatingByteArray(0xAA, 16))
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, expectedRealmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt claims contains invalid 'aud' field")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt claims have an invalid 'aud' field
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{"0102030405060708091011121314151617"},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, expectedRealmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt claims contains invalid 'aud' field")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt claims has additional realms in 'aud' field
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String(), "secondaudience"},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt claims contains invalid 'aud' field")
	assert.Nil(t, verifiedClaims)

	// Test when the jwt claims has no realms in 'aud' field
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "artemis",
				Issuer:  "apollo",
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeUser)
	assert.EqualError(t, err, "jwt claims contains invalid 'aud' field")
	assert.Nil(t, verifiedClaims)

	// Test scope doesn't match required scope
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, requireScope, scopeAudit)
	assert.EqualError(t, err, "jwt claims 'scope' missing audit scope")
	assert.Nil(t, verifiedClaims)

	// Test explicit scope doesn't match optional scope
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
			Scope: scopeUser,
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeAudit)
	assert.EqualError(t, err, "jwt claims 'scope' missing audit scope")
	assert.Nil(t, verifiedClaims)

	// Test scope is empty but required
	token = &jwt.Token{
		Header: header,
		Claims: &claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "artemis",
				Issuer:   "apollo",
				Audience: []string{realmID.String()},
			},
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, requireScope, scopeAudit)
	assert.EqualError(t, err, "jwt claims missing 'scope' field")
	assert.Nil(t, verifiedClaims)

	// Test scope is set to an unknown scope
	token.Claims = &claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "artemis",
			Issuer:   "apollo",
			Audience: []string{realmID.String()},
		},
		Scope: "list",
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeAudit)
	assert.EqualError(t, err, "jwt claims 'scope' missing audit scope")
	assert.Nil(t, verifiedClaims)

	// Test scope is empty, but not required.
	token.Claims = &claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "artemis",
			Issuer:   "apollo",
			Audience: []string{realmID.String()},
		},
	}
	c.Set("user", token)
	verifiedClaims, err = verifyToken(c, realmID, allowMissingScope, scopeAudit)
	assert.NoError(t, err)
	assert.Equal(t, token.Claims, verifiedClaims)
}
