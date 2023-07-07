package requests

import (
	"testing"

	"github.com/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalCBOR(t *testing.T) {
	// With a string payload
	data := []byte{105, 82, 101, 103, 105, 115, 116, 101, 114, 49}
	sr := &SecretsRequest{}
	err := sr.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Equal(t, Register1{}, sr.Payload)

	// Test with a map payload
	data = []byte{0xa1, 0x68, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x33, 0xa2, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x50, 0x05, 0x0a, 0x9d, 0xab, 0x91, 0xf6, 0x36, 0x76, 0xbe, 0x18, 0xd1, 0x18, 0x94, 0x9c, 0x1b, 0x4f, 0x6e, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x74, 0x61, 0x67, 0x50, 0x90, 0xad, 0x6d, 0xd4, 0xd6, 0x3b, 0x99, 0xd0, 0x6b, 0x6d, 0x3e, 0xb8, 0xd0, 0x8f, 0x5b, 0x1d}
	sr = &SecretsRequest{}
	err = sr.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Equal(t, Recover3{
		Version:      types.RegistrationVersion{0x5, 0xa, 0x9d, 0xab, 0x91, 0xf6, 0x36, 0x76, 0xbe, 0x18, 0xd1, 0x18, 0x94, 0x9c, 0x1b, 0x4f},
		UnlockKeyTag: types.UnlockKeyTag{0x90, 0xad, 0x6d, 0xd4, 0xd6, 0x3b, 0x99, 0xd0, 0x6b, 0x6d, 0x3e, 0xb8, 0xd0, 0x8f, 0x5b, 0x1d},
	}, sr.Payload)

	// Test with an unknown payload
	data = []byte{0x64, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e}
	sr = &SecretsRequest{}
	err = sr.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Nil(t, sr.Payload)
}
