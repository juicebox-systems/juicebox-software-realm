package types

import (
	"crypto/subtle"
	"encoding/hex"
)

type ProviderName int

const (
	GCP ProviderName = iota
	AWS
	Mongo
	Memory
)

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

type EncryptionKeyScalarShare [32]byte
type EncryptedSecret [145]byte
type EncryptedSecretCommitment [16]byte

type Policy struct {
	NumGuesses uint16 `cbor:"num_guesses"`
}

func (x UnlockKeyTag) ConstantTimeCompare(y UnlockKeyTag) int {
	return subtle.ConstantTimeCompare(x[:], y[:])
}
