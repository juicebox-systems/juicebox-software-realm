package responses

import "github.com/juicebox-systems/juicebox-software-realm/types"

type Register1 struct{}

type Register2 struct{}

type Recover1 struct {
	Version types.RegistrationVersion `cbor:"version"`
}

type Recover2 struct {
	OprfSignedPublicKey types.OprfSignedPublicKey `cbor:"oprf_signed_public_key"`
	OprfBlindedResult   types.OprfBlindedResult   `cbor:"oprf_blinded_result"`
	OprfProof           types.OprfProof           `cbor:"oprf_proof"`
	UnlockKeyCommitment types.UnlockKeyCommitment `cbor:"unlock_key_commitment"`
	NumGuesses          uint16                    `cbor:"num_guesses"`
	GuessCount          uint16                    `cbor:"guess_count"`
}

type Recover3 struct {
	EncryptionKeyScalarShare  *types.EncryptionKeyScalarShare  `cbor:"encryption_key_scalar_share,omitempty"`
	EncryptedSecret           *types.EncryptedSecret           `cbor:"encrypted_secret,omitempty"`
	EncryptedSecretCommitment *types.EncryptedSecretCommitment `cbor:"encrypted_secret_commitment,omitempty"`
	GuessesRemaining          *uint16                          `cbor:"guesses_remaining,omitempty"`
}

type Delete struct{}
