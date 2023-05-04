package types

import (
	"crypto/subtle"
)

// Because cbor encodes []byte as strings, we use []uint16
// to represent our byte arrays. Ideally, the package can
// be patched to allow an EncOption to encode []byte as
// a cbor array.

type Salt [32]uint16

type OprfKey [32]uint16
type OprfBlindedInput [32]uint16
type OprfBlindedResult [32]uint16

type MaskedTgkShare [64]uint16
type SecretShare [146]uint16

type Policy struct {
	NumGuesses uint16 `cbor:"num_guesses"`
}

type UnlockTag [32]uint16

func (x UnlockTag) ConstantTimeCompare(y UnlockTag) int {
	return subtle.ConstantTimeCompare(ByteSlice(x[:]), ByteSlice(y[:]))
}

// this unsafely assumes the uint16 is actually a uint8
func ByteSlice(input []uint16) []byte {
	output := make([]byte, len(input))
	for i, b := range input {
		output[i] = uint8(b)
	}
	return output
}

func Uint16Slice(input []byte) []uint16 {
	output := make([]uint16, len(input))
	for i, b := range input {
		output[i] = uint16(b)
	}
	return output
}
