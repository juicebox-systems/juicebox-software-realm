package router

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/records"
	"github.com/juicebox-systems/juicebox-software-realm/secrets"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/labstack/echo/v4"
)

const requireScope = true
const allowMissingScope = false
const scopeUser = "user"
const scopeAudit = "audit"

func userRecordID(c echo.Context, realmID types.RealmID) (*records.UserRecordID, *claims, error) {
	claims, err := verifyToken(c, realmID, allowMissingScope, scopeUser)
	if err != nil {
		return nil, nil, err
	}
	userRecordID, err := records.CreateUserRecordID(claims.Issuer, claims.Subject)
	if err != nil {
		return nil, nil, err
	}
	return &userRecordID, claims, nil
}

func verifyToken(c echo.Context, realmID types.RealmID, scopeRequired bool, scope string) (*claims, error) {
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return nil, errors.New("user is not a jwt token")
	}

	claims, ok := token.Claims.(*claims)
	if !ok {
		return nil, errors.New("jwt claims of unexpected type")
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != realmID.String() {
		return nil, errors.New("jwt claims contains invalid 'aud' field")
	}

	if claims.Subject == "" {
		return nil, errors.New("jwt claims missing 'sub' field")
	}
	if claims.Issuer == "" {
		return nil, errors.New("jwt claims missing 'iss' field")
	}
	tenantName := claims.Issuer

	signingTenantName, _, err := secrets.ParseKid(token)
	if err != nil {
		return nil, err
	}
	if *signingTenantName != tenantName {
		return nil, errors.New("jwt 'iss' field does not match signer")
	}

	if claims.Scope != scope {
		if claims.Scope == "" {
			if scopeRequired {
				return nil, errors.New("jwt claims missing 'scope' field")
			}
		} else {
			return nil, fmt.Errorf("jwt claims 'scope' should be '%s'", scope)
		}
	}
	return claims, nil
}

type claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope,omitempty"`
}
