package types

import (
	"crypto/subtle"
)

type ProviderName string

const (
	GCP    ProviderName = "gcp"
	AWS    ProviderName = "aws"
	Memory ProviderName = "memory"
)

type Salt [32]byte

type OprfKey [32]byte
type OprfBlindedInput [32]byte
type OprfBlindedResult [32]byte

type MaskedTgkShare [33]byte
type SecretShare [146]byte

type Policy struct {
	NumGuesses uint16 `cbor:"num_guesses"`
}

type UnlockTag [32]byte

func (x UnlockTag) ConstantTimeCompare(y UnlockTag) int {
	return subtle.ConstantTimeCompare(x[:], y[:])
}
