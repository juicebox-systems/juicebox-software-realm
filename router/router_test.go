package router

import (
	"net/http"
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
	e := echo.New()
	r := http.Request{}
	c := e.NewContext(&r, nil)
	tenantID := "test"

	oprfKey := types.OprfKey{0xf5, 0xa9, 0x9e, 0x3e, 0xf0, 0x9f, 0x0b, 0x6b, 0xbc, 0x89, 0x21, 0x82, 0x7f, 0x32, 0xe8, 0x8e, 0x96, 0xbe, 0x30, 0x6c, 0x76, 0x6c, 0x89, 0xf7, 0xa8, 0xfa, 0xba, 0xae, 0xc2, 0xed, 0x16, 0x0c}
	oprfBlindedInput := types.OprfBlindedInput{0xe6, 0x92, 0xd0, 0xf3, 0x22, 0x96, 0xe9, 0x01, 0x97, 0xf4, 0x55, 0x7c, 0x74, 0x42, 0x99, 0xd2, 0x3e, 0x1d, 0xc2, 0x6c, 0xda, 0x1a, 0xea, 0x5a, 0xa7, 0x54, 0xb4, 0x6c, 0xee, 0x59, 0x55, 0x7c}
	oprfBlindedResult := types.OprfBlindedResult{0x40, 0x1b, 0x49, 0x14, 0x43, 0x34, 0xa2, 0x09, 0x3d, 0xac, 0xf6, 0xbd, 0x5c, 0xc2, 0x54, 0x0d, 0x66, 0x6a, 0x14, 0xc4, 0x18, 0x79, 0x71, 0x2e, 0xfb, 0xe9, 0xb0, 0x1d, 0x85, 0x65, 0xa1, 0x57}

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
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        oprfKey,
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
	}
	expectedUserRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        oprfKey,
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     0,
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
		Salt: types.Salt(makeRepeatingByteArray(1, 32)),
	}
	expectedResponse.Status = responses.Ok
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 2 Registered
	request.Payload = requests.Recover2{
		BlindedOprfInput: oprfBlindedInput,
	}
	expectedResponse.Payload = responses.Recover2{
		BlindedOprfResult: oprfBlindedResult,
		MaskedTgkShare:    types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
	}
	expectedResponse.Status = responses.Ok
	expectedUserRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        oprfKey,
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     1,
	}
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
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
		OprfKey:        oprfKey,
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     0,
	}
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
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
		OprfKey:        oprfKey,
		UnlockTag:      types.UnlockTag(makeRepeatingByteArray(3, 32)),
		MaskedTgkShare: types.MaskedTgkShare(makeRepeatingByteArray(1, 33)),
		SecretShare:    types.SecretShare(makeRepeatingByteArray(1, 146)),
		Policy:         types.Policy{NumGuesses: 2},
		GuessCount:     1,
	}
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecord, *updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	userRecord.RegistrationState = records.Registered{
		Salt:           types.Salt(makeRepeatingByteArray(1, 32)),
		OprfKey:        oprfKey,
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
	request.Payload = requests.Recover2{}
	expectedResponse.Payload = responses.Recover2{}
	expectedResponse.Status = responses.NoGuesses
	response, updatedRecord, err = HandleRequest(c, tenantID, userRecord, request)
	assert.NoError(t, err)
	assert.Nil(t, updatedRecord)
	assert.Equal(t, expectedResponse, *response)

	// Recover 3 NoGuesses
	request.Payload = requests.Recover3{}
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
	claims := &jwt.RegisteredClaims{
		Subject: "artemis",
		Issuer:  "apollo",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create a mock Echo context with the user token
	e := echo.New()
	c := e.NewContext(nil, nil)
	c.Set("user", token)

	userRecordID, tenantID, err := UserRecordID(c)

	expectedUserRecordID := records.UserRecordID("8e240996ec810cb6dd09f89257200181763136ded36a0cd843c8c0212b95dae1")
	assert.NoError(t, err)
	assert.Equal(t, expectedUserRecordID, *userRecordID)
	assert.Equal(t, "apollo", *tenantID)

	// Test when the user is not a jwt token
	c.Set("user", "not a jwt token")
	userRecordID, tenantID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "user is not a jwt token")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims are of unexpected type
	invalidToken := jwt.New(jwt.SigningMethodHS256)
	c.Set("user", invalidToken)
	userRecordID, tenantID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims of unexpected type")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims missing 'sub' field
	claims.Subject = ""
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims missing 'sub' field")
	assert.Nil(t, userRecordID)
	assert.Nil(t, tenantID)

	// Test when the jwt claims missing 'iss' field
	claims.Issuer = ""
	claims.Subject = "apollo"
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)
	userRecordID, tenantID, err = UserRecordID(c)
	assert.Error(t, err)
	assert.EqualError(t, err, "jwt claims missing 'iss' field")
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
