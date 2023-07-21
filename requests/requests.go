package requests

import (
	"github.com/juicebox-software-realm/types"
)

type Register1 struct{}

type Register2 struct {
	Version                            types.RegistrationVersion
	OprfKey                            types.OprfKey                            `cbor:"oprf_key"`
	UnlockKeyCommitment                types.UnlockKeyCommitment                `cbor:"unlock_key_commitment"`
	UnlockKeyTag                       types.UnlockKeyTag                       `cbor:"unlock_key_tag"`
	UserSecretEncryptionKeyScalarShare types.UserSecretEncryptionKeyScalarShare `cbor:"user_secret_encryption_key_scalar_share"`
	EncryptedUserSecret                types.EncryptedUserSecret                `cbor:"encrypted_user_secret"`
	EncryptedUserSecretCommitment      types.EncryptedUserSecretCommitment      `cbor:"encrypted_user_secret_commitment"`
	Policy                             types.Policy
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
