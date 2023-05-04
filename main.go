package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt"
	"github.com/juicebox-software-realm/records"
	"github.com/juicebox-software-realm/requests"
	"github.com/juicebox-software-realm/responses"
	"github.com/juicebox-software-realm/types"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/blake2s"
)

// todo: store records
var memoryRecords = map[records.UserRecordId]records.UserRecord{}

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// TODO: pull real secrets
	e.Use(middleware.JWT([]byte("an-auth-token-key")))

	e.POST("/req", func(c echo.Context) error {
		body, err := ioutil.ReadAll(c.Request().Body)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Error reading request body")
		}

		var request requests.SecretsRequest
		err = cbor.Unmarshal(body, &request)
		if err != nil {
			return c.String(http.StatusBadRequest, "Error unmarshalling request body")
		}

		userRecordId := userRecordId(c)
		userRecord := memoryRecords[userRecordId]
		if userRecord.RegistrationState == nil {
			userRecord.RegistrationState = records.NotRegistered{}
		}

		response, updatedUserRecord, err := handleRequest(userRecord, request)
		if err != nil {
			return c.String(http.StatusBadRequest, "Error processing request")
		}

		if updatedUserRecord != nil {
			memoryRecords[userRecordId] = *updatedUserRecord
		}

		serializedResponse, err := cbor.Marshal(response)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Error marshalling response payload")
		}

		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEOctetStream)
		return c.Blob(http.StatusOK, echo.MIMEOctetStream, serializedResponse)
	})

	e.Logger.Fatal(e.Start(":8080"))
}

func userRecordId(c echo.Context) records.UserRecordId {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)

	// Extract user and tenant from JWT claims
	userID := claims["sub"].(string)
	tenantID := claims["iss"].(string)

	hash := blake2s.Sum256([]byte(fmt.Sprintf("%s|%s", tenantID, userID)))

	return records.UserRecordId(hash)
}

func handleRequest(record records.UserRecord, request requests.SecretsRequest) (*responses.SecretsResponse, *records.UserRecord, error) {
	switch o := request.Payload.(type) {
	case requests.Register1:
		return &responses.SecretsResponse{
			Status:  responses.Ok,
			Payload: responses.Register1{},
		}, nil, nil
	case requests.Register2:
		record.RegistrationState = records.Registered{
			OprfKey:        o.OprfKey,
			Salt:           o.Salt,
			MaskedTgkShare: o.MaskedTgkShare,
			SecretShare:    o.SecretShare,
			UnlockTag:      o.UnlockTag,
			GuessCount:     0,
			Policy:         o.Policy,
		}
		return &responses.SecretsResponse{
			Status:  responses.Ok,
			Payload: responses.Register2{},
		}, &record, nil
	case requests.Recover1:
		switch t := record.RegistrationState.(type) {
		case records.Registered:
			if t.GuessCount >= uint16(t.Policy.NumGuesses) {
				record.RegistrationState = records.NoGuesses{}
				return &responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover1{},
				}, &record, nil
			}

			return &responses.SecretsResponse{
				Status: responses.Ok,
				Payload: responses.Recover1{
					Salt: t.Salt,
				},
			}, nil, nil
		case records.NoGuesses:
			return &responses.SecretsResponse{
				Status:  responses.NoGuesses,
				Payload: responses.Recover1{},
			}, nil, nil
		case records.NotRegistered:
			return &responses.SecretsResponse{
				Status:  responses.NotRegistered,
				Payload: responses.Recover1{},
			}, nil, nil
		}
	case requests.Recover2:
		switch t := record.RegistrationState.(type) {
		case records.Registered:
			if t.GuessCount >= uint16(t.Policy.NumGuesses) {
				record.RegistrationState = records.NoGuesses{}
				return &responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover2{},
				}, &record, nil
			}

			t.GuessCount += 1
			record.RegistrationState = t

			key := oprf.PrivateKey{}
			key.UnmarshalBinary(oprf.SuiteRistretto255, types.ByteSlice(t.OprfKey[:]))

			blindedPin := group.Ristretto255.NewElement()
			blindedPin.UnmarshalBinary(types.ByteSlice(o.BlindedPin[:]))

			server := oprf.NewServer(oprf.SuiteRistretto255, &key)
			req := oprf.EvaluationRequest{Elements: []oprf.Blinded{blindedPin}}
			blindedOprfPin, err := server.Evaluate(&req)
			if err != nil {
				return nil, &record, err
			}

			serializedBlindedOprfPin, err := blindedOprfPin.Elements[0].MarshalBinary()
			if err != nil {
				return nil, &record, err
			}

			return &responses.SecretsResponse{
				Status: responses.Ok,
				Payload: responses.Recover2{
					BlindedOprfPin: types.OprfBlindedResult(types.Uint16Slice(serializedBlindedOprfPin)),
					MaskedTgkShare: t.MaskedTgkShare,
				},
			}, &record, nil
		case records.NoGuesses:
			return &responses.SecretsResponse{
				Status:  responses.NoGuesses,
				Payload: responses.Recover2{},
			}, nil, nil
		case records.NotRegistered:
			return &responses.SecretsResponse{
				Status:  responses.NotRegistered,
				Payload: responses.Recover2{},
			}, nil, nil
		}
	case requests.Recover3:
		switch t := record.RegistrationState.(type) {
		case records.Registered:
			guessesRemaining := t.Policy.NumGuesses - t.GuessCount

			if o.UnlockTag.ConstantTimeCompare(t.UnlockTag) != 1 {
				if guessesRemaining == 0 {
					record.RegistrationState = records.NoGuesses{}
				}

				return &responses.SecretsResponse{
					Status: responses.BadUnlockTag,
					Payload: responses.Recover3{
						GuessesRemaining: &guessesRemaining,
					},
				}, &record, nil
			}

			t.GuessCount = 0
			record.RegistrationState = t

			return &responses.SecretsResponse{
				Status: responses.Ok,
				Payload: responses.Recover3{
					SecretShare: t.SecretShare,
				},
			}, &record, nil
		case records.NoGuesses:
			return &responses.SecretsResponse{
				Status:  responses.NoGuesses,
				Payload: responses.Recover3{},
			}, nil, nil
		case records.NotRegistered:
			return &responses.SecretsResponse{
				Status:  responses.NotRegistered,
				Payload: responses.Recover3{},
			}, nil, nil
		}
	case requests.Delete:
		record.RegistrationState = records.NotRegistered{}
		return &responses.SecretsResponse{
			Status:  responses.Ok,
			Payload: responses.Delete{},
		}, &record, nil
	}

	return nil, nil, fmt.Errorf("Unexpected request type")
}
