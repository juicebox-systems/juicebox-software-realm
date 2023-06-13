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
	oprfBlindedResult := types.OprfBlindedResult{0xee, 0x8d, 0x91, 0x39, 0xf7, 0x3e, 0xe8, 0x5, 0x99, 0xb7, 0x19, 0x4a, 0x15, 0x57, 0x2d, 0x88, 0x38, 0xb9, 0x31, 0x41, 0x13, 0x29, 0x99, 0x57, 0xa7, 0x48, 0x25, 0x1a, 0xf9, 0x6a, 0x76, 0x27}

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
		Version:              types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		SaltShare:            types.SaltShare(makeRepeatingByteArray(1, 17)),
		OprfSeed:             types.OprfSeed(makeRepeatingByteArray(2, 32)),
		UnlockTag:            types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedUnlockKeyShare: types.MaskedUnlockKeyShare(makeRepeatingByteArray(1, 33)),
		SecretShare:          types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:               types.Policy{NumGuesses: 2},
	}
	expectedUserRecord.RegistrationState = records.Registered{
		Version:              types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		SaltShare:            types.SaltShare(makeRepeatingByteArray(1, 17)),
		OprfSeed:             types.OprfSeed(makeRepeatingByteArray(2, 32)),
		UnlockTag:            types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedUnlockKeyShare: types.MaskedUnlockKeyShare(makeRepeatingByteArray(1, 33)),
		SecretShare:          types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:               types.Policy{NumGuesses: 2},
		GuessCount:           0,
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
		Version:   types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		SaltShare: types.SaltShare(makeRepeatingByteArray(1, 17)),
	}
	expectedResponse.Status = responses.Ok
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 2 Registered
	request.Payload = requests.Recover2{
		Version:          types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		BlindedOprfInput: oprfBlindedInput,
	}
	expectedResponse.Payload = responses.Recover2{
		BlindedOprfResult:    oprfBlindedResult,
		MaskedUnlockKeyShare: types.MaskedUnlockKeyShare(makeRepeatingByteArray(1, 33)),
	}
	expectedResponse.Status = responses.Ok
	expectedUserRecord.RegistrationState = records.Registered{
		Version:              types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		SaltShare:            types.SaltShare(makeRepeatingByteArray(1, 17)),
		OprfSeed:             types.OprfSeed(makeRepeatingByteArray(2, 32)),
		UnlockTag:            types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedUnlockKeyShare: types.MaskedUnlockKeyShare(makeRepeatingByteArray(1, 33)),
		SecretShare:          types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:               types.Policy{NumGuesses: 2},
		GuessCount:           1,
	}
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 3 Correct Unlock Tag
	request.Payload = requests.Recover3{
		Version:   types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		UnlockTag: types.UnlockTag(makeRepeatingByteArray(3, 32)),
	}
	expectedResponse.Payload = responses.Recover3{
		SecretShare: types.SecretShare(makeRepeatingByteArray(1, 146)),
	}
	expectedResponse.Status = responses.Ok
	expectedUserRecord.RegistrationState = records.Registered{
		Version:              types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		SaltShare:            types.SaltShare(makeRepeatingByteArray(1, 17)),
		OprfSeed:             types.OprfSeed(makeRepeatingByteArray(2, 32)),
		UnlockTag:            types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedUnlockKeyShare: types.MaskedUnlockKeyShare(makeRepeatingByteArray(1, 33)),
		SecretShare:          types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:               types.Policy{NumGuesses: 2},
		GuessCount:           0,
	}
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 Wrong Unlock Tag, Guesses Remaining
	request.Payload = requests.Recover3{
		Version:   types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		UnlockTag: types.UnlockTag(makeRepeatingByteArray(5, 32)),
	}
	guessesRemaining := uint16(1)
	expectedResponse.Payload = responses.Recover3{
		GuessesRemaining: &guessesRemaining,
	}
	expectedResponse.Status = responses.BadUnlockTag
	expectedUserRecord.RegistrationState = records.Registered{
		Version:              types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		SaltShare:            types.SaltShare(makeRepeatingByteArray(1, 17)),
		OprfSeed:             types.OprfSeed(makeRepeatingByteArray(2, 32)),
		UnlockTag:            types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedUnlockKeyShare: types.MaskedUnlockKeyShare(makeRepeatingByteArray(1, 33)),
		SecretShare:          types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:               types.Policy{NumGuesses: 2},
		GuessCount:           1,
	}
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord.RegistrationState = records.Registered{
		Version:              types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		SaltShare:            types.SaltShare(makeRepeatingByteArray(1, 17)),
		OprfSeed:             types.OprfSeed(makeRepeatingByteArray(2, 32)),
		UnlockTag:            types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedUnlockKeyShare: types.MaskedUnlockKeyShare(makeRepeatingByteArray(1, 33)),
		SecretShare:          types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:               types.Policy{NumGuesses: 2},
		GuessCount:           2,
	}

	// Recover 3 Wrong Unlock Tag, No Guesses Remaining
	request.Payload = requests.Recover3{
		Version:   types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
		UnlockTag: types.UnlockTag(makeRepeatingByteArray(5, 32)),
	}
	guessesRemaining = 0
	expectedResponse.Payload = responses.Recover3{
		GuessesRemaining: &guessesRemaining,
	}
	expectedResponse.Status = responses.BadUnlockTag
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
		Version: types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
	}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 NoGuesses
	request.Payload = requests.Recover3{
		Version: types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
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
		Version: types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
	}

	request.Payload = requests.Recover2{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
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
		Version: types.RegistrationVersion(makeRepeatingByteArray(10, 16)),
	}

	request.Payload = requests.Recover3{
		Version: types.RegistrationVersion(makeRepeatingByteArray(1, 16)),
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

	expectedUserRecordID := records.UserRecordID("8e240996ec810cb6dd09f89257200181763136ded36a0cd843c8c0212b95dae1")
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
