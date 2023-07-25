package requests

import (
	"github.com/juicebox-software-realm/types"
)

type Register1 struct{}

type Register2 struct {
	Version                   types.RegistrationVersion
	OprfPrivateKey            types.OprfPrivateKey            `cbor:"oprf_private_key"`
	OprfSignedPublicKey       types.OprfSignedPublicKey       `cbor:"oprf_signed_public_key"`
	UnlockKeyCommitment       types.UnlockKeyCommitment       `cbor:"unlock_key_commitment"`
	UnlockKeyTag              types.UnlockKeyTag              `cbor:"unlock_key_tag"`
	EncryptionKeyScalarShare  types.EncryptionKeyScalarShare  `cbor:"encryption_key_scalar_share"`
	EncryptedSecret           types.EncryptedSecret           `cbor:"encrypted_secret"`
	EncryptedSecretCommitment types.EncryptedSecretCommitment `cbor:"encrypted_secret_commitment"`
	Policy                    types.Policy
}

type Recover1 struct{}

type Recover2 struct {
	Version          types.RegistrationVersion
	OprfBlindedInput types.OprfBlindedInput `cbor:"oprf_blinded_input"`
}

type Recover3 struct {
	Version      types.RegistrationVersion
	UnlockKeyTag types.UnlockKeyTag `cbor:"unlock_key_tag"`
}

type Delete struct{}
