package records

import (
	"testing"

	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

func TestMarshalCBOR(t *testing.T) {
	// Test with a Registered state
	record := &UserRecord{
		RegistrationState: Registered{
			Version:        types.RegistrationVersion(makeRepeatingByteArray(0, 16)),
			OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(1, 32)),
			OprfSignedPublicKey: types.OprfSignedPublicKey{
				PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
				VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
				Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
			},
			UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(2, 32)),
			UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(3, 16)),
			EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(4, 32)),
			EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(5, 145)),
			EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(6, 16)),
			GuessCount:                16,
			Policy: types.Policy{
				NumGuesses: 5,
			},
		},
	}
	expectedData := []byte{0xa1, 0x6a, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0xaa, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0x6f, 0x70, 0x72, 0x66, 0x5f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x76, 0x6f, 0x70, 0x72, 0x66, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0xa3, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x6d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x69, 0x6e, 0x67, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x58, 0x40, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x75, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x58, 0x20, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x6e, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x74, 0x61, 0x67, 0x50, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x78, 0x1b, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x63, 0x61, 0x6c, 0x61, 0x72, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x58, 0x20, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x70, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x58, 0x91, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x78, 0x1b, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x50, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6b, 0x67, 0x75, 0x65, 0x73, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x10, 0x66, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0xa1, 0x6b, 0x6e, 0x75, 0x6d, 0x5f, 0x67, 0x75, 0x65, 0x73, 0x73, 0x65, 0x73, 0x5}
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
	data := []byte{0xa1, 0x6a, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0xaa, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0x6f, 0x70, 0x72, 0x66, 0x5f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x76, 0x6f, 0x70, 0x72, 0x66, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0xa3, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x6d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x69, 0x6e, 0x67, 0x5f, 0x6b, 0x65, 0x79, 0x58, 0x20, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x58, 0x40, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x75, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x58, 0x20, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x6e, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x74, 0x61, 0x67, 0x50, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x78, 0x1b, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x63, 0x61, 0x6c, 0x61, 0x72, 0x5f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x58, 0x20, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x70, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x58, 0x91, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x78, 0x1b, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x50, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6, 0x6b, 0x67, 0x75, 0x65, 0x73, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x10, 0x66, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0xa1, 0x6b, 0x6e, 0x75, 0x6d, 0x5f, 0x67, 0x75, 0x65, 0x73, 0x73, 0x65, 0x73, 0x5}
	expectedRecord := &UserRecord{
		RegistrationState: Registered{
			Version:        types.RegistrationVersion(makeRepeatingByteArray(0, 16)),
			OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(1, 32)),
			OprfSignedPublicKey: types.OprfSignedPublicKey{
				PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
				VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
				Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
			},
			UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(2, 32)),
			UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(3, 16)),
			EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(4, 32)),
			EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(5, 145)),
			EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(6, 16)),
			GuessCount:                16,
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
	data = []byte{0x64, 0x55, 0x6e, 0x6b, 0x6e}
	err = record.UnmarshalCBOR(data)
	assert.Error(t, err)
	assert.EqualError(t, err, "cbor: cannot unmarshal UTF-8 text string into Go value of type map[string]cbor.RawMessage")
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
