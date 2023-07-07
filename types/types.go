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

type OprfSeed [32]byte
type OprfBlindedInput [32]byte
type OprfBlindedResult [32]byte

type MaskedUnlockKeyScalarShare [32]byte
type UnlockKeyCommitment [32]byte
type UnlockKeyTag [16]byte

type UserSecretEncryptionKeyScalarShare [32]byte
type EncryptedUserSecret [145]byte
type EncryptedUserSecretCommitment [16]byte

type Policy struct {
	NumGuesses uint16 `cbor:"num_guesses"`
}

func (x UnlockKeyTag) ConstantTimeCompare(y UnlockKeyTag) int {
	return subtle.ConstantTimeCompare(x[:], y[:])
}
