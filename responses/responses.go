package responses

import "github.com/juicebox-software-realm/types"

type Register1 struct{}

type Register2 struct{}

type Recover1 struct {
	Salt types.Salt `cbor:"salt"`
}

type Recover2 struct {
	BlindedOprfPin types.OprfBlindedResult `cbor:"blinded_oprf_pin"`
	MaskedTgkShare types.MaskedTgkShare    `cbor:"masked_tgk_share"`
}

type Recover3 struct {
	SecretShare      types.SecretShare `cbor:"secret_share,omitempty"`
	GuessesRemaining *uint16           `cbor:"guesses_remaining,omitempty"`
}

type Delete struct{}
