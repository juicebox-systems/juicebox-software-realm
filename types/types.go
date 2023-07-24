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

type OprfPrivateKey [32]byte
type OprfBlindedInput [32]byte
type OprfBlindedResult [32]byte

type OprfPublicKeySignature struct {
	VerifyingKey [32]byte `cbor:"verifying_key"`
	Bytes        [64]byte `cbor:"bytes"`
}

type OprfSignedPublicKey struct {
	PublicKey [32]byte               `cbor:"public_key"`
	Signature OprfPublicKeySignature `cbor:"signature"`
}

type UnlockKeyCommitment [32]byte
type UnlockKeyTag [16]byte

type EncryptionKeyScalarShare [32]byte
type EncryptedSecret [145]byte
type EncryptedSecretCommitment [16]byte

type Policy struct {
	NumGuesses uint16 `cbor:"num_guesses"`
}

func (x UnlockKeyTag) ConstantTimeCompare(y UnlockKeyTag) int {
	return subtle.ConstantTimeCompare(x[:], y[:])
}
