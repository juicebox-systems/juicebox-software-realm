package responses

import "github.com/juicebox-software-realm/types"

type Register1 struct{}

type Register2 struct{}

type Recover1 struct {
	Version types.RegistrationVersion `cbor:"version"`
}

type Recover2 struct {
	OprfBlindedResult          types.OprfBlindedResult          `cbor:"oprf_blinded_result"`
	MaskedUnlockKeyScalarShare types.MaskedUnlockKeyScalarShare `cbor:"masked_unlock_key_scalar_share"`
	UnlockKeyCommitment        types.UnlockKeyCommitment        `cbor:"unlock_key_commitment"`
}

type Recover3 struct {
	UserSecretEncryptionKeyScalarShare *types.UserSecretEncryptionKeyScalarShare `cbor:"user_secret_encryption_key_scalar_share,omitempty"`
	EncryptedUserSecret                *types.EncryptedUserSecret                `cbor:"encrypted_user_secret,omitempty"`
	EncryptedUserSecretCommitment      *types.EncryptedUserSecretCommitment      `cbor:"encrypted_user_secret_commitment,omitempty"`
	GuessesRemaining                   *uint16                                   `cbor:"guesses_remaining,omitempty"`
}

type Delete struct{}
