package router

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/pubsub"
	"github.com/juicebox-systems/juicebox-software-realm/records"
	"github.com/juicebox-systems/juicebox-software-realm/requests"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

var HandleRequest = handleRequest

func TestHandleRequest(t *testing.T) {
	e := echo.New()
	r := http.Request{}
	c := e.NewContext(&r, nil)
	claims := &claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "test",
			Subject: "121314",
		}}
	hashedUserID := "447ddec5f08c757d40e7acb9f1bc10ed44a960683bb991f5e4ed17498f786ff8"

	oprfBlindedInput := types.OprfBlindedInput{0xe6, 0x92, 0xd0, 0xf3, 0x22, 0x96, 0xe9, 0x01, 0x97, 0xf4, 0x55, 0x7c, 0x74, 0x42, 0x99, 0xd2, 0x3e, 0x1d, 0xc2, 0x6c, 0xda, 0x1a, 0xea, 0x5a, 0xa7, 0x54, 0xb4, 0x6c, 0xee, 0x59, 0x55, 0x7c}
	oprfBlindedResult := types.OprfBlindedResult{0x1c, 0x63, 0xe0, 0x37, 0xd5, 0x99, 0x2, 0x32, 0xa8, 0xfd, 0x52, 0xd9, 0x89, 0x83, 0x82, 0xfc, 0xe1, 0x88, 0xe0, 0xcc, 0xe3, 0x18, 0x57, 0x82, 0x9e, 0x3b, 0x93, 0xf9, 0x77, 0xc0, 0x79, 0x5c}

	userRecord := records.UserRecord{
		RegistrationState: records.NotRegistered{},
	}
	expectedUserRecord := records.UserRecord{}
	request := requests.SecretsRequest{}
	expectedResponse := responses.SecretsResponse{}

	// Register 1
	request.Payload = requests.Register1{}
	expectedResponse.Payload = responses.Register1{}
	expectedResponse.Status = responses.Ok
	result, err := HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Register 2
	request.Payload = requests.Register2{
		Version:        types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(2, 32)),
		OprfSignedPublicKey: types.OprfSignedPublicKey{
			PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
			VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
			Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
		},
		UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(3, 32)),
		UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(4, 16)),
		EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(5, 32)),
		EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(6, 145)),
		EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(7, 16)),
		Policy:                    types.Policy{NumGuesses: 2},
	}
	expectedUserRecord.RegistrationState = records.Registered{
		Version:        types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(2, 32)),
		OprfSignedPublicKey: types.OprfSignedPublicKey{
			PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
			VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
			Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
		},
		UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(3, 32)),
		UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(4, 16)),
		EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(5, 32)),
		EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(6, 145)),
		EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(7, 16)),
		Policy:                    types.Policy{NumGuesses: 2},
		GuessCount:                0,
	}
	expectedResponse.Payload = responses.Register2{}
	expectedResponse.Status = responses.Ok
	expectedEvent := &pubsub.EventMessage{Event: "registered", User: hashedUserID}
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Equal(t, expectedEvent, result.event)

	userRecord = *result.updatedRecord

	// Recover 1 Registered
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}
	expectedResponse.Status = responses.Ok
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Recover 2 Registered
	request.Payload = requests.Recover2{
		Version:          types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		OprfBlindedInput: oprfBlindedInput,
	}
	expectedResponse.Payload = responses.Recover2{
		OprfSignedPublicKey: types.OprfSignedPublicKey{
			PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
			VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
			Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
		},
		OprfBlindedResult: oprfBlindedResult,
		OprfProof: types.OprfProof{
			C:     [32]uint8{0xfc, 0x9a, 0xdf, 0x81, 0x39, 0xc3, 0xc9, 0x2a, 0x14, 0x66, 0x1f, 0x31, 0x4a, 0xe1, 0x9b, 0x96, 0xc4, 0x48, 0x6, 0x28, 0xed, 0xcb, 0xac, 0xff, 0x92, 0x43, 0xa4, 0x7b, 0xe9, 0xe0, 0xd8, 0x2},
			BetaZ: [32]uint8{0x62, 0x14, 0xeb, 0x40, 0x77, 0x72, 0x3d, 0xde, 0x98, 0xbd, 0x51, 0x9a, 0x77, 0x7d, 0x5f, 0x54, 0xc8, 0x17, 0xad, 0xd, 0x2, 0xc4, 0x40, 0xf9, 0x93, 0x96, 0xb9, 0x8, 0xa6, 0xd7, 0x77, 0x3},
		},
		UnlockKeyCommitment: types.UnlockKeyCommitment(makeRepeatingByteArray(3, 32)),
		NumGuesses:          2,
		GuessCount:          1,
	}
	expectedResponse.Status = responses.Ok
	expectedUserRecord.RegistrationState = records.Registered{
		Version:        types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(2, 32)),
		OprfSignedPublicKey: types.OprfSignedPublicKey{
			PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
			VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
			Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
		},
		UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(3, 32)),
		UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(4, 16)),
		EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(5, 32)),
		EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(6, 145)),
		EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(7, 16)),
		Policy:                    types.Policy{NumGuesses: 2},
		GuessCount:                1,
	}
	betaTSeed, err := hex.DecodeString("d26f293ccf9cb05517a385986605134a1ce6036ae560bbea8f32745db5a13746c25db6612a8ff96c03a84b5b963061b405fca21a6b80ddfbbb9f4b6a5deffe68")
	var expectedGuessCount uint16 = 1
	var expectedNumGuesses uint16 = 2
	expectedEvent = &pubsub.EventMessage{Event: "guess_used", User: hashedUserID, GuessCount: &expectedGuessCount, NumGuesses: &expectedNumGuesses}
	assert.NoError(t, err)
	rng := bytes.NewReader(betaTSeed)
	result, err = HandleRequest(c, claims, userRecord, request, rng)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Equal(t, result.event, expectedEvent)

	userRecord = *result.updatedRecord

	// Recover 3 Correct Unlock Tag
	request.Payload = requests.Recover3{
		Version:      types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		UnlockKeyTag: types.UnlockKeyTag(makeRepeatingByteArray(4, 16)),
	}
	expectedUserSecretEncryptionKeyScalarShare := types.EncryptionKeyScalarShare(makeRepeatingByteArray(5, 32))
	expectedEncryptedUserSecret := types.EncryptedSecret(makeRepeatingByteArray(6, 145))
	expectedEncryptedUserSecretCommitment := types.EncryptedSecretCommitment(makeRepeatingByteArray(7, 16))
	expectedResponse.Payload = responses.Recover3{
		EncryptionKeyScalarShare:  &expectedUserSecretEncryptionKeyScalarShare,
		EncryptedSecret:           &expectedEncryptedUserSecret,
		EncryptedSecretCommitment: &expectedEncryptedUserSecretCommitment,
	}
	expectedResponse.Status = responses.Ok
	expectedUserRecord.RegistrationState = records.Registered{
		Version:        types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(2, 32)),
		OprfSignedPublicKey: types.OprfSignedPublicKey{
			PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
			VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
			Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
		},
		UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(3, 32)),
		UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(4, 16)),
		EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(5, 32)),
		EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(6, 145)),
		EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(7, 16)),
		Policy:                    types.Policy{NumGuesses: 2},
		GuessCount:                0,
	}
	expectedEvent = &pubsub.EventMessage{Event: "share_recovered", User: hashedUserID}
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Equal(t, expectedEvent, result.event)

	// Recover 3 Wrong Unlock Tag, Guesses Remaining
	request.Payload = requests.Recover3{
		Version:      types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		UnlockKeyTag: types.UnlockKeyTag(makeRepeatingByteArray(10, 16)),
	}
	guessesRemaining := uint16(1)
	expectedResponse.Payload = responses.Recover3{
		GuessesRemaining: &guessesRemaining,
	}
	expectedResponse.Status = responses.BadUnlockKeyTag
	expectedUserRecord.RegistrationState = records.Registered{
		Version:        types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(2, 32)),
		OprfSignedPublicKey: types.OprfSignedPublicKey{
			PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
			VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
			Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
		},
		UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(3, 32)),
		UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(4, 16)),
		EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(5, 32)),
		EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(6, 145)),
		EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(7, 16)),
		Policy:                    types.Policy{NumGuesses: 2},
		GuessCount:                1,
	}
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	userRecord.RegistrationState = records.Registered{
		Version:        types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		OprfPrivateKey: types.OprfPrivateKey(makeRepeatingByteArray(2, 32)),
		OprfSignedPublicKey: types.OprfSignedPublicKey{
			PublicKey:    [32]byte(makeRepeatingByteArray(1, 32)),
			VerifyingKey: [32]byte(makeRepeatingByteArray(2, 32)),
			Signature:    [64]byte(makeRepeatingByteArray(3, 64)),
		},
		UnlockKeyCommitment:       types.UnlockKeyCommitment(makeRepeatingByteArray(3, 32)),
		UnlockKeyTag:              types.UnlockKeyTag(makeRepeatingByteArray(4, 16)),
		EncryptionKeyScalarShare:  types.EncryptionKeyScalarShare(makeRepeatingByteArray(5, 32)),
		EncryptedSecret:           types.EncryptedSecret(makeRepeatingByteArray(6, 145)),
		EncryptedSecretCommitment: types.EncryptedSecretCommitment(makeRepeatingByteArray(7, 16)),
		Policy:                    types.Policy{NumGuesses: 2},
		GuessCount:                2,
	}

	// Recover 3 Wrong Unlock Tag, No Guesses Remaining
	request.Payload = requests.Recover3{
		Version:      types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
		UnlockKeyTag: types.UnlockKeyTag(makeRepeatingByteArray(10, 16)),
	}
	guessesRemaining = 0
	expectedResponse.Payload = responses.Recover3{
		GuessesRemaining: &guessesRemaining,
	}
	expectedResponse.Status = responses.BadUnlockKeyTag
	expectedUserRecord.RegistrationState = records.NoGuesses{}
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	userRecord = *result.updatedRecord

	// Recover 1 NoGuesses
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{}
	expectedResponse.Status = responses.NoGuesses
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Recover 2 NoGuesses
	request.Payload = requests.Recover2{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NoGuesses
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Recover 3 NoGuesses
	request.Payload = requests.Recover3{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}
	expectedResponse.Payload = responses.Recover3{}
	expectedResponse.Status = responses.NoGuesses
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Delete
	userRecord.RegistrationState = records.Registered{}
	request.Payload = requests.Delete{}
	expectedUserRecord.RegistrationState = records.NotRegistered{}
	expectedResponse.Payload = responses.Delete{}
	expectedResponse.Status = responses.Ok
	expectedEvent = &pubsub.EventMessage{Event: "deleted", User: hashedUserID}
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Equal(t, expectedEvent, result.event)

	userRecord = *result.updatedRecord

	// Recover 1 NotRegistered
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{}
	expectedResponse.Status = responses.NotRegistered
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Recover 2 NotRegistered
	request.Payload = requests.Recover2{}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NotRegistered
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Recover 3 NotRegistered
	request.Payload = requests.Recover3{}
	expectedResponse.Payload = responses.Recover3{}
	expectedResponse.Status = responses.NotRegistered
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Recover 2 VersionMismatch
	userRecord.RegistrationState = records.Registered{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}

	request.Payload = requests.Recover2{
		Version: types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
	}
	guessesRemaining = 0
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.VersionMismatch
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Recover 3 VersionMismatch
	userRecord.RegistrationState = records.Registered{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}

	request.Payload = requests.Recover3{
		Version: types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
	}
	guessesRemaining = 0
	expectedResponse.Payload = responses.Recover3{}
	expectedResponse.Status = responses.VersionMismatch
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.NoError(t, err)
	assert.Nil(t, result.updatedRecord)
	assert.Equal(t, expectedResponse, result.response)
	assert.Nil(t, result.event)

	// Invalid request
	request.Payload = "invalid"
	result, err = HandleRequest(c, claims, userRecord, request, nil)
	assert.Error(t, err)
	assert.EqualError(t, err, "unexpected request type")
	assert.Nil(t, result)
}

func makeRepeatingByteArray(value byte, length int) []byte {
	array := make([]byte, length)
	for i := 0; i < length; i++ {
		array[i] = value
	}
	return array
}
