package router

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/juicebox-software-realm/providers"
	"github.com/juicebox-software-realm/records"
	"github.com/juicebox-software-realm/requests"
	"github.com/juicebox-software-realm/responses"
	"github.com/juicebox-software-realm/types"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/blake2s"
)

func NewRouter(
	realmId uuid.UUID,
	provider *providers.Provider,
	disableTls bool,
	port int,
) {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	jwtConfig := middleware.DefaultJWTConfig
	jwtConfig.KeyFunc = provider.SecretsManager.GetJWTSigningKey

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{"realm_id": realmId})
	})

	e.POST("/req", func(c echo.Context) error {
		body, error := ioutil.ReadAll(c.Request().Body)
		if error != nil {
			return c.String(http.StatusInternalServerError, "Error reading request body")
		}

		var request requests.SecretsRequest
		error = cbor.Unmarshal(body, &request)
		if error != nil {
			return c.String(http.StatusBadRequest, "Error unmarshalling request body")
		}

		userRecordId, error := userRecordId(c)
		if error != nil {
			return c.String(http.StatusBadRequest, "Error reading user from jwt")
		}

		userRecord, error := provider.RecordStore.GetRecord(*userRecordId)
		if error != nil {
			return c.String(http.StatusInternalServerError, "Error reading from record store")
		}

		response, updatedUserRecord, error := handleRequest(userRecord, request)
		if error != nil {
			return c.String(http.StatusBadRequest, "Error processing request")
		}

		if updatedUserRecord != nil {
			error := provider.RecordStore.WriteRecord(*userRecordId, *updatedUserRecord)
			if error != nil {
				return c.String(http.StatusInternalServerError, "Error writing to record store")
			}
		}

		serializedResponse, error := cbor.Marshal(response)
		if error != nil {
			return c.String(http.StatusInternalServerError, "Error marshalling response payload")
		}

		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEOctetStream)
		return c.Blob(http.StatusOK, echo.MIMEOctetStream, serializedResponse)
	}, middleware.JWTWithConfig(jwtConfig))

	if disableTls {
		e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
	} else {
		e.AutoTLSManager.Cache = autocert.DirCache("/var/www/.cache")
		e.Logger.Fatal(e.StartAutoTLS(fmt.Sprintf(":%d", port)))
	}
}

func userRecordId(c echo.Context) (*records.UserRecordId, error) {
	user, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return nil, errors.New("user is not a jwt token")
	}

	claims, ok := user.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("jwt claims of unexpected type")
	}

	sub, ok := claims["sub"]
	if !ok {
		return nil, errors.New("jwt claims missing 'sub' field")
	}
	userId, ok := sub.(string)
	if !ok {
		return nil, errors.New("jwt 'sub' is not a string")
	}

	iss, ok := claims["iss"]
	if !ok {
		return nil, errors.New("jwt claims missing 'iss' field")
	}
	tenantId, ok := iss.(string)
	if !ok {
		return nil, errors.New("jwt 'iss' is not a string")
	}

	hash := blake2s.Sum256([]byte(fmt.Sprintf("%s|%s", tenantId, userId)))
	userRecordId := records.UserRecordId(hex.EncodeToString(hash[:]))

	return &userRecordId, nil
}

func handleRequest(record records.UserRecord, request requests.SecretsRequest) (*responses.SecretsResponse, *records.UserRecord, error) {
	switch payload := request.Payload.(type) {
	case requests.Register1:
		return &responses.SecretsResponse{
			Status:  responses.Ok,
			Payload: responses.Register1{},
		}, nil, nil
	case requests.Register2:
		record.RegistrationState = records.Registered{
			OprfKey:        payload.OprfKey,
			Salt:           payload.Salt,
			MaskedTgkShare: payload.MaskedTgkShare,
			SecretShare:    payload.SecretShare,
			UnlockTag:      payload.UnlockTag,
			GuessCount:     0,
			Policy:         payload.Policy,
		}
		return &responses.SecretsResponse{
			Status:  responses.Ok,
			Payload: responses.Register2{},
		}, &record, nil
	case requests.Recover1:
		switch state := record.RegistrationState.(type) {
		case records.Registered:
			if state.GuessCount >= uint16(state.Policy.NumGuesses) {
				record.RegistrationState = records.NoGuesses{}
				return &responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover1{},
				}, &record, nil
			}

			return &responses.SecretsResponse{
				Status: responses.Ok,
				Payload: responses.Recover1{
					Salt: state.Salt,
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
		switch state := record.RegistrationState.(type) {
		case records.Registered:
			if state.GuessCount >= uint16(state.Policy.NumGuesses) {
				record.RegistrationState = records.NoGuesses{}
				return &responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover2{},
				}, &record, nil
			}

			state.GuessCount += 1
			record.RegistrationState = state

			key := oprf.PrivateKey{}
			key.UnmarshalBinary(oprf.SuiteRistretto255, state.OprfKey[:])

			blindedPin := group.Ristretto255.NewElement()
			blindedPin.UnmarshalBinary(payload.BlindedOprfInput[:])

			server := oprf.NewServer(oprf.SuiteRistretto255, &key)
			req := oprf.EvaluationRequest{Elements: []oprf.Blinded{blindedPin}}
			blindedOprfResult, error := server.Evaluate(&req)
			if error != nil {
				return nil, &record, error
			}

			serializedBlindedOprfResult, error := blindedOprfResult.Elements[0].MarshalBinary()
			if error != nil {
				return nil, &record, error
			}

			return &responses.SecretsResponse{
				Status: responses.Ok,
				Payload: responses.Recover2{
					BlindedOprfResult: types.OprfBlindedResult(serializedBlindedOprfResult),
					MaskedTgkShare:    state.MaskedTgkShare,
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
		switch state := record.RegistrationState.(type) {
		case records.Registered:
			guessesRemaining := state.Policy.NumGuesses - state.GuessCount

			if payload.UnlockTag.ConstantTimeCompare(state.UnlockTag) != 1 {
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

			state.GuessCount = 0
			record.RegistrationState = state

			return &responses.SecretsResponse{
				Status: responses.Ok,
				Payload: responses.Recover3{
					SecretShare: state.SecretShare,
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

	return nil, nil, errors.New("Unexpected request type")
}
