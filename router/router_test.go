package router

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/juicebox-software-realm/records"
	"github.com/juicebox-software-realm/requests"
	"github.com/juicebox-software-realm/responses"
	"github.com/juicebox-software-realm/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

var HandleRequest = handleRequest

func TestHandleRequest(t *testing.T) {
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
	response, updatedRecord, err := HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Register 2
	request.Payload = requests.Register2{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        types.OprfKey(makeRepeatingByteArray(2, 32)),
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
	}
	expectedUserRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        types.OprfKey(makeRepeatingByteArray(2, 32)),
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     0,
	}
	expectedResponse.Payload = responses.Register2{}
	expectedResponse.Status = responses.Ok
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 1 Registered
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{
		Salt: types.Salt(makeRepeatingByteArray(1, 32)),
	}
	expectedResponse.Status = responses.Ok
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 2 Registered
	request.Payload = requests.Recover2{
		BlindedOprfInput: types.OprfBlindedInput(makeRepeatingByteArray(1, 32)),
	}
	expectedResponse.Payload = responses.Recover2{
		BlindedOprfResult: types.OprfBlindedResult(makeRepeatingByteArray(0, 32)),
		MaskedTgkShare:    types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
	}
	expectedResponse.Status = responses.Ok
	expectedUserRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        types.OprfKey(makeRepeatingByteArray(2, 32)),
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     1,
	}
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 3 Correct Unlock Tag
	request.Payload = requests.Recover3{
		UnlockTag: types.UnlockTag(makeRepeatingByteArray(3, 32)),
	}
	expectedResponse.Payload = responses.Recover3{
		SecretShare: types.SecretShare(makeRepeatingByteArray(1, 146)),
	}
	expectedResponse.Status = responses.Ok
	expectedUserRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        types.OprfKey(makeRepeatingByteArray(2, 32)),
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     0,
	}
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 Wrong Unlock Tag, Guesses Remaining
	request.Payload = requests.Recover3{
		UnlockTag: types.UnlockTag(makeRepeatingByteArray(5, 32)),
	}
	guessesRemaining := uint16(1)
	expectedResponse.Payload = responses.Recover3{
		GuessesRemaining: &guessesRemaining,
	}
	expectedResponse.Status = responses.BadUnlockTag
	expectedUserRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        types.OprfKey(makeRepeatingByteArray(2, 32)),
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     1,
	}
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        types.OprfKey(makeRepeatingByteArray(2, 32)),
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     2,
	}

	// Recover 3 Wrong Unlock Tag, No Guesses Remaining
	request.Payload = requests.Recover3{
		UnlockTag: types.UnlockTag(makeRepeatingByteArray(5, 32)),
	}
	guessesRemaining = 0
	expectedResponse.Payload = responses.Recover3{
		GuessesRemaining: &guessesRemaining,
	}
	expectedResponse.Status = responses.BadUnlockTag
	expectedUserRecord.RegistrationState = records.NoGuesses{}
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 1 NoGuesses
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 2 NoGuesses
	request.Payload = requests.Recover2{}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 NoGuesses
	request.Payload = requests.Recover3{}
	expectedResponse.Payload = responses.Recover3{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Delete
	userRecord.RegistrationState = records.Registered{}
	request.Payload = requests.Delete{}
	expectedUserRecord.RegistrationState = records.NotRegistered{}
	expectedResponse.Payload = responses.Delete{}
	expectedResponse.Status = responses.Ok
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord = *updatedRecord

	// Recover 1 NotRegistered
	request.Payload = requests.Recover1{}
	expectedResponse.Payload = responses.Recover1{}
	expectedResponse.Status = responses.NotRegistered
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 2 NotRegistered
	request.Payload = requests.Recover2{}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NotRegistered
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 NotRegistered
	request.Payload = requests.Recover3{}
	expectedResponse.Payload = responses.Recover3{}
	expectedResponse.Status = responses.NotRegistered
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Invalid request
	request.Payload = "invalid"
	response, updatedRecord, err = HandleRequest(userRecord, request)
	assert.Error(t, err)
	assert.EqualError(t, err, "unexpected request type")
	assert.Nil(t, response)
	assert.Nil(t, updatedRecord)
}

var UserRecordID = userRecordID

func TestUserRecordID(t *testing.T) {
	// Create a mock user token
	claims := &jwt.RegisteredClaims{
		Subject: "artemis",
		Issuer:  "apollo",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create a mock Echo context with the user token
	e := echo.New()
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	userRecordID, err := UserRecordID(c)

	expectedUserRecordID := records.UserRecordID("8e240996ec810cb6dd09f89257200181763136ded36a0cd843c8c0212b95dae1")
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecordID, *userRecordID)

	// Test when the user is not a jwt token
	c.Set("user", "not a jwt token")
	userRecordID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "user is not a jwt token")
	assert.Nil(t, userRecordID)

	// Test when the jwt claims are of unexpected type
	invalidToken := jwt.New(jwt.SigningMethodHS256)
	c.Set("user", invalidToken)
	userRecordID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims of unexpected type")
	assert.Nil(t, userRecordID)

	// Test when the jwt claims missing 'sub' field
	claims.Subject = ""
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)
	userRecordID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims missing 'sub' field")
	assert.Nil(t, userRecordID)

	// Test when the jwt claims missing 'iss' field
	claims.Issuer = ""
	claims.Subject = "apollo"
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)
	userRecordID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims missing 'iss' field")
	assert.Nil(t, userRecordID)
}

func makeRepeatingByteArray(value byte, length int) []byte {
	array := make([]byte, length)
	for i := 0; i < length; i++ {
		array[i] = value
	}
	return array
}
