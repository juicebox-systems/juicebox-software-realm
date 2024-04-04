package types

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/labstack/echo/v4"
)

type ProviderName int

const (
	GCP ProviderName = iota
	AWS
	Mongo
	Memory
)

type ProviderOptions struct {
	Config interface{}
}

type RealmID [16]byte

func (id RealmID) String() string {
	return hex.EncodeToString(id[:])
}

const JuiceboxRealmDatabasePrefix string = "jb-sw-realm-"
const JuiceboxTenantSecretPrefix string = "jb-sw-tenant-"

type RegistrationVersion [16]byte

type OprfPrivateKey [32]byte
type OprfPublicKey [32]byte
type OprfBlindedInput [32]byte
type OprfBlindedResult [32]byte

type OprfSignedPublicKey struct {
	PublicKey    OprfPublicKey `cbor:"public_key"`
	VerifyingKey [32]byte      `cbor:"verifying_key"`
	Signature    [64]byte      `cbor:"signature"`
}

type OprfProof struct {
	C     [32]byte `cbor:"c"`
	BetaZ [32]byte `cbor:"beta_z"`
}

type UnlockKeyCommitment [32]byte
type UnlockKeyTag [16]byte

func (x UnlockKeyTag) ConstantTimeCompare(y UnlockKeyTag) int {
	return subtle.ConstantTimeCompare(x[:], y[:])
}

type EncryptionKeyScalarShare [32]byte
type EncryptedSecret [145]byte
type EncryptedSecretCommitment [16]byte

type Policy struct {
	NumGuesses uint16 `cbor:"num_guesses"`
}

type AuthKeyAlgorithm string

const (
	/// RSASSA-PKCS1-v1_5 using SHA-256
	RS256 AuthKeyAlgorithm = "RsaPkcs1Sha256"
	/// HMAC using SHA-256
	HS256 AuthKeyAlgorithm = "HmacSha256"
	/// Edwards-curve 25519 Digital Signature Algorithm
	EdDSA AuthKeyAlgorithm = "Edwards25519"
)

func (aka AuthKeyAlgorithm) Matches(alg string) bool {
	lowerAlg := strings.ToLower(alg)
	return (aka == HS256 && lowerAlg == "hs256") || (aka == RS256 && lowerAlg == "rs256") || (aka == EdDSA && lowerAlg == "eddsa")
}

type AuthKeyDataEncoding string

const (
	Hex  AuthKeyDataEncoding = "Hex"
	UTF8 AuthKeyDataEncoding = "UTF8"
)

type AuthKeyJSON struct {
	Data      string              `json:"data"`
	Encoding  AuthKeyDataEncoding `json:"encoding"`
	Algorithm AuthKeyAlgorithm    `json:"algorithm"`
}

type HTTPError struct {
	Err  error
	Code int
}

func NewHTTPError(code int, e error) *HTTPError {
	if e == nil {
		return nil
	}
	if he, ok := e.(*HTTPError); ok {
		return he
	}
	// The caller may of wrapped a HttpError to add additional context to the
	// message. Ensure we preserve the wrapped status code.
	var wrapped *HTTPError
	if errors.As(e, &wrapped) {
		code = wrapped.Code
	}
	return &HTTPError{
		Err:  e,
		Code: code,
	}
}

func (e *HTTPError) Error() string {
	return e.Err.Error()
}

func (e *HTTPError) StatusCode() int {
	return e.Code
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

func (e *HTTPError) ToEcho() *echo.HTTPError {
	// We can't use Echo's HTTPError everywhere because it adds code=blah into
	// the Error() output which makes wrapping it for additional context
	// problematic.
	return echo.NewHTTPError(e.Code, e.Err)
}
