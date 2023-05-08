package records

import (
	"testing"

	"github.com/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

func TestMarshalCBOR(t *testing.T) {
	// Test with a Registered state
	record := &UserRecord{
		RegistrationState: Registered{
			OprfKey:        types.OprfKey(makeRepeatingByteArray(1, 32)),
			Salt:           types.Salt(makeRepeatingByteArray(2, 32)),
			MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(5, 33)),
			SecretShare:    types.SecretShare(makeRepeatingByteArray(12, 146)),
			UnlockTag:      types.UnlockTag(makeRepeatingByteArray(99, 32)),
			GuessCount:     16,
			Policy: types.Policy{
				NumGuesses: 5,
			},
		},
	}
	expectedData := []byte{0xa1, 0x6a, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0xa7, 0x68, 0x6f, 0x70, 0x72, 0x66, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x64, 0x73, 0x61, 0x6c, 0x74, 0x58, 0x20, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x70, 0x6d, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x5f, 0x74, 0x67, 0x6b, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x58, 0x21, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x6c, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x58, 0x92, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0x6a, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x74, 0x61, 0x67, 0x58, 0x20, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x6b, 0x67, 0x75, 0x65, 0x73, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x10, 0x66, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0xa1, 0x6b, 0x6e, 0x75, 0x6d, 0x5f, 0x67, 0x75, 0x65, 0x73, 0x73, 0x65, 0x73, 0x5}
	data, err := record.MarshalCBOR()
	assert.NoError(t, err)
	assert.Equal(t, expectedData, data)

	// Test with a NotRegistered state
	record = &UserRecord{
		RegistrationState: NotRegistered{},
	}
	expectedData = []byte{0xa1, 0x6d, 0x4e, 0x6f, 0x74, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0xa0}
	data, err = record.MarshalCBOR()
	assert.NoError(t, err)
	assert.Equal(t, expectedData, data)

	// Test with a NoGuesses state
	record = &UserRecord{
		RegistrationState: NoGuesses{},
	}
	expectedData = []byte{0xa1, 0x69, 0x4e, 0x6f, 0x47, 0x75, 0x65, 0x73, 0x73, 0x65, 0x73, 0xa0}
	data, err = record.MarshalCBOR()
	assert.NoError(t, err)
	assert.Equal(t, expectedData, data)
}

func TestUnmarshalCBOR(t *testing.T) {
	// Test with a Registered state
	data := []byte{0xa1, 0x6a, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0xa7, 0x68, 0x6f, 0x70, 0x72, 0x66, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x64, 0x73, 0x61, 0x6c, 0x74, 0x58, 0x20, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x70, 0x6d, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x5f, 0x74, 0x67, 0x6b, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x58, 0x21, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x6c, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x58, 0x92, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0xc, 0x6a, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x74, 0x61, 0x67, 0x58, 0x20, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x6b, 0x67, 0x75, 0x65, 0x73, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x10, 0x66, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0xa1, 0x6b, 0x6e, 0x75, 0x6d, 0x5f, 0x67, 0x75, 0x65, 0x73, 0x73, 0x65, 0x73, 0x5}
	expectedRecord := &UserRecord{
		RegistrationState: Registered{
			OprfKey:        types.OprfKey(makeRepeatingByteArray(1, 32)),
			Salt:           types.Salt(makeRepeatingByteArray(2, 32)),
			MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(5, 33)),
			SecretShare:    types.SecretShare(makeRepeatingByteArray(12, 146)),
			UnlockTag:      types.UnlockTag(makeRepeatingByteArray(99, 32)),
			GuessCount:     16,
			Policy: types.Policy{
				NumGuesses: 5,
			},
		},
	}
	var record UserRecord
	err := record.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Equal(t, expectedRecord, &record)

	// Test with a NotRegistered state
	record.RegistrationState = nil
	data = []byte{0xa1, 0x6d, 0x4e, 0x6f, 0x74, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0xa0}
	expectedRecord = &UserRecord{
		RegistrationState: NotRegistered{},
	}
	err = record.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Equal(t, expectedRecord, &record)

	// Test with a NoGuesses state
	record.RegistrationState = nil
	data = []byte{0xa1, 0x69, 0x4e, 0x6f, 0x47, 0x75, 0x65, 0x73, 0x73, 0x65, 0x73, 0xa0}
	expectedRecord = &UserRecord{
		RegistrationState: NoGuesses{},
	}
	err = record.UnmarshalCBOR(data)
	assert.NoError(t, err)
	assert.Equal(t, expectedRecord, &record)

	// Test with an unknown data
	record.RegistrationState = nil
	data = []byte{0x64, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e}
	err = record.UnmarshalCBOR(data)
	assert.Error(t, err)
	assert.EqualError(t, err, "cbor: cannot unmarshal UTF-8 text string into Go value of type map[interface {}]interface {}")
	assert.Nil(t, record.RegistrationState)

	// Test with an invalid state
	record.RegistrationState = nil
	data = []byte{0xa1, 0x60, 0xa1, 0x67, 0x61, 0x72, 0x74, 0x65, 0x6d, 0x69, 0x73, 0x66, 0x61, 0x70, 0x6f, 0x6c, 0x6c, 0x6f}
	err = record.UnmarshalCBOR(data)
	assert.Error(t, err)
	assert.EqualError(t, err, "unexpected registration state")
	assert.Nil(t, record.RegistrationState)
}

func makeRepeatingByteArray(value byte, length int) []byte {
	array := make([]byte, length)
	for i := 0; i < length; i++ {
		array[i] = value
	}
	return array
}
