package requests

import (
	"github.com/juicebox-software-realm/types"
)

type Register1 struct{}

type Register2 struct {
	Salt           types.Salt
	OprfKey        types.OprfKey        `cbor:"oprf_key"`
	UnlockTag      types.UnlockTag      `cbor:"tag"`
	MaskedTgkShare types.MaskedTgkShare `cbor:"masked_tgk_share"`
	SecretShare    types.SecretShare    `cbor:"secret_share"`
	Policy         types.Policy
}

type Recover1 struct{}

type Recover2 struct {
	BlindedPin types.OprfBlindedInput `cbor:"blinded_pin"`
}

type Recover3 struct {
	UnlockTag types.UnlockTag `cbor:"tag"`
}

type Delete struct{}
