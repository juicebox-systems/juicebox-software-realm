package responses

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalCBOR(t *testing.T) {
	// Test with an empty payload
	sr := &SecretsResponse{
		Payload: Register1{},
		Status:  Ok,
	}
	expectedData := []byte{0xa1, 0x69, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x31, 0x62, 0x4f, 0x6b}
	data, err := sr.MarshalCBOR()
	assert.NoError(t, err)
	assert.Equal(t, expectedData, data)

	// Test with a non-empty payload
	guessesRemaining := uint16(5)
	sr = &SecretsResponse{
		Payload: Recover3{GuessesRemaining: &guessesRemaining},
		Status:  NotRegistered,
	}
	expectedData = []byte{0xa1, 0x68, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x33, 0xa1, 0x6d, 0x4e, 0x6f, 0x74, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0xa1, 0x71, 0x67, 0x75, 0x65, 0x73, 0x73, 0x65, 0x73, 0x5f, 0x72, 0x65, 0x6d, 0x61, 0x69, 0x6e, 0x69, 0x6e, 0x67, 0x5}
	data, err = sr.MarshalCBOR()
	assert.NoError(t, err)
	assert.Equal(t, expectedData, data)
}

var IsEmptyInterface = isEmptyInterface

func TestIsEmptyInterface(t *testing.T) {
	// Test with an empty struct
	empty := struct{}{}
	assert.True(t, IsEmptyInterface(empty))

	// Test with a non-empty struct
	nonEmpty := struct {
		Name string
	}{"artemis"}
	assert.False(t, IsEmptyInterface(nonEmpty))

	// Test with a primitive type
	assert.False(t, IsEmptyInterface(42))

	// Test with a nil value
	var nilValue interface{}
	assert.False(t, IsEmptyInterface(nilValue))

	// Test with a struct containing an empty string field
	structWithEmptyString := struct {
		Name string
	}{}
	assert.True(t, IsEmptyInterface(structWithEmptyString))

	// Test with a struct containing a non-empty string field
	structWithNonEmptyString := struct {
		Name string
	}{Name: "apollo"}
	assert.False(t, IsEmptyInterface(structWithNonEmptyString))
}
