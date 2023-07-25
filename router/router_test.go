package router

import (
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/juicebox-software-realm/records"
	"github.com/juicebox-software-realm/requests"
	"github.com/juicebox-software-realm/responses"
	"github.com/juicebox-software-realm/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

var HandleRequest = handleRequest

func TestHandleRequest(t *testing.T) {
	e := echo.New()
	r := http.Request{}
	c := e.NewContext(&r, nil)
	tenantID := "test"

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
	response, updatedRecord, err := HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

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
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 1 Registered
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}
	expectedResponse.Status = responses.Ok
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

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
		OprfBlindedResult:   oprfBlindedResult,
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
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

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
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

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
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

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
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 1 NoGuesses
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 2 NoGuesses
	request.Payload = requests.Recover2{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 NoGuesses
	request.Payload = requests.Recover3{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
	}
	expectedResponse.Payload = responses.Recover3{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Delete
	userRecord.RegistrationState = records.Registered{}
	request.Payload = requests.Delete{}
	expectedUserRecord.RegistrationState = records.NotRegistered{}
	expectedResponse.Payload = responses.Delete{}
	expectedResponse.Status = responses.Ok
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 1 NotRegistered
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{}
	expectedResponse.Status = responses.NotRegistered
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 2 NotRegistered
	request.Payload = requests.Recover2{}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NotRegistered
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 NotRegistered
	request.Payload = requests.Recover3{}
	expectedResponse.Payload = responses.Recover3{}
	expectedResponse.Status = responses.NotRegistered
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

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
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

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
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Invalid request
	request.Payload = "invalid"
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.Error(t, err)
	assert.EqualError(t, err, "unexpected request type")
	assert.Nil(t, response)
	assert.Nil(t, updatedRecord)
}

var UserRecordID = userRecordID

func TestUserRecordID(t *testing.T) {
	// Create a mock user token
	realmID, err := uuid.NewRandom()
	assert.NoError(t, err)
	claims := &jwt.RegisteredClaims{
		Subject:  "artemis",
		Issuer:   "apollo",
		Audience: []string{strings.ReplaceAll(realmID.String(), "-", "")},
	}
	header := map[string]interface{}{
		"kid": "apollo:1",
	}
	token := &jwt.Token{
		Header: header,
		Claims: claims,
	}

	// Create a mock Echo context with the user token
	e := echo.New()
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	userRecordID, tenantID, err := UserRecordID(c, realmID)

	expectedUserRecordID := records.UserRecordID("1033250bfb2d27fd2a7fccba346851d517700a3ea5155429d5b5845875db75d3")
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecordID, *userRecordID)
	assert.Equal(t, "apollo", *tenantID)

	// Test when the user is not a jwt token
	c.Set("user", "not a jwt token")
	userRecordID, tenantID, err = UserRecordID(c, realmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "user is not a jwt token")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims are of unexpected type
	invalidToken := &jwt.Token{
		Header: header,
	}
	c.Set("user", invalidToken)
	userRecordID, tenantID, err = UserRecordID(c, realmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims of unexpected type")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims missing 'sub' field
	claims.Subject = ""
	token = &jwt.Token{
		Header: header,
		Claims: claims,
	}
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c, realmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims missing 'sub' field")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims missing 'iss' field
	claims.Issuer = ""
	claims.Subject = "apollo"
	token = &jwt.Token{
		Header: header,
		Claims: claims,
	}
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c, realmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims missing 'iss' field")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt signer does not match the 'iss' field
	claims.Issuer = "apollo"
	header["kid"] = "artemis:1"
	token = &jwt.Token{
		Header: header,
		Claims: claims,
	}
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c, realmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt 'iss' field does not match signer")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims has invalid 'aud' field
	token = &jwt.Token{
		Header: header,
		Claims: claims,
	}
	expectedRealmID, err := uuid.NewRandom()
	assert.NoError(t, err)
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c, expectedRealmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims contains invalid 'aud' field")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims has additional realms in 'aud' field
	claims.Audience = append(claims.Audience, "secondaudience")
	token = &jwt.Token{
		Header: header,
		Claims: claims,
	}
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c, realmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims contains invalid 'aud' field")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims has no realms in 'aud' field
	claims.Audience = []string{}
	token = &jwt.Token{
		Header: header,
		Claims: claims,
	}
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c, realmID)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims contains invalid 'aud' field")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)
}

func makeRepeatingByteArray(value byte, length int) []byte {
	array := make([]byte, length)
	for i := 0; i < length; i++ {
		array[i] = value
	}
	return array
}
