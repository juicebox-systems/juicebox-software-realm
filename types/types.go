package types

import (
	"crypto/subtle"
)

type ProviderName int

const (
	GCP ProviderName = iota
	AWS
	Mongo
	Memory
)

const JuiceboxRealmDatabasePrefix string = "jb-sw-realm-"
const JuiceboxTenantSecretPrefix string = "jb-sw-tenant-"

type RegistrationVersion [16]byte

type SaltShare [17]byte

type OprfSeed [32]byte
type OprfBlindedInput [32]byte
type OprfBlindedResult [32]byte

type MaskedUnlockKeyShare [33]byte
type SecretShare [146]byte

type Policy struct {
	NumGuesses uint16 `cbor:"num_guesses"`
}

type UnlockTag [32]byte

func (x UnlockTag) ConstantTimeCompare(y UnlockTag) int {
	return subtle.ConstantTimeCompare(x[:], y[:])
}
