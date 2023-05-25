package requests

import (
	"github.com/juicebox-software-realm/types"
)

type Register1 struct{}

type Register2 struct {
	Version        types.RegistrationVersion
	SaltShare      types.SaltShare      `cbor:"salt_share"`
	OprfSeed       types.OprfSeed       `cbor:"oprf_seed"`
	UnlockTag      types.UnlockTag      `cbor:"tag"`
	MaskedTgkShare types.MaskedTgkShare `cbor:"masked_tgk_share"`
	SecretShare    types.SecretShare    `cbor:"secret_share"`
	Policy         types.Policy
}

type Recover1 struct{}

type Recover2 struct {
	Version          types.RegistrationVersion
	BlindedOprfInput types.OprfBlindedInput `cbor:"blinded_oprf_input"`
}

type Recover3 struct {
	Version   types.RegistrationVersion
	UnlockTag types.UnlockTag `cbor:"tag"`
}

type Delete struct{}
