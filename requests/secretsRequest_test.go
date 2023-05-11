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
	data = []byte{161, 104, 82, 101, 99, 111, 118, 101, 114, 51, 161, 99, 116, 97, 103, 88, 32, 53, 132, 164, 75, 32, 210, 122, 88, 107, 230, 170, 16, 122, 224, 196, 4, 63, 100, 228, 90, 121, 63, 99, 179, 249, 240, 49, 39, 2, 191, 10, 205}
	sr = &SecretsRequest{}
	err = sr.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Equal(t, Recover3{
		UnlockTag: types.UnlockTag{0x35, 0x84, 0xa4, 0x4b, 0x20, 0xd2, 0x7a, 0x58, 0x6b, 0xe6, 0xaa, 0x10, 0x7a, 0xe0, 0xc4, 0x4, 0x3f, 0x64, 0xe4, 0x5a, 0x79, 0x3f, 0x63, 0xb3, 0xf9, 0xf0, 0x31, 0x27, 0x2, 0xbf, 0xa, 0xcd},
	}, sr.Payload)

	// Test with an unknown payload
	data = []byte{0x64, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e}
	sr = &SecretsRequest{}
	err = sr.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Nil(t, sr.Payload)
}
