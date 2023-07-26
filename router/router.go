package router

import (
	"context"
	cryptoRand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/juicebox-software-realm/otel"
	"github.com/juicebox-software-realm/providers"
	"github.com/juicebox-software-realm/records"
	"github.com/juicebox-software-realm/requests"
	"github.com/juicebox-software-realm/responses"
	"github.com/juicebox-software-realm/secrets"
	"github.com/juicebox-software-realm/voprf"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func RunRouter(
	realmID uuid.UUID,
	provider *providers.Provider,
	port uint64,
) {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimit("2K"))
	e.Use(middleware.CORS())
	e.Use(otelecho.Middleware("echo-router"))

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{"realmID": realmID})
	})

	e.POST("/req", func(c echo.Context) error {
		userRecordID, tenantID, err := userRecordID(c, realmID)
		if err != nil {
			return contextAwareError(c, http.StatusUnauthorized, "Error reading user from jwt")
		}

		body, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return contextAwareError(c, http.StatusInternalServerError, "Error reading request body")
		}

		var request requests.SecretsRequest
		err = cbor.Unmarshal(body, &request)
		if err != nil {
			return contextAwareError(c, http.StatusBadRequest, "Error unmarshalling request body")
		}

		userRecord, readRecord, err := provider.RecordStore.GetRecord(c.Request().Context(), *userRecordID)
		if err != nil {
			return contextAwareError(c, http.StatusInternalServerError, "Error reading from record store")
		}

		response, updatedUserRecord, err := handleRequest(c, *tenantID, userRecord, request)
		if err != nil {
			return contextAwareError(c, http.StatusBadRequest, "Error processing request")
		}

		if updatedUserRecord != nil {
			err := provider.RecordStore.WriteRecord(c.Request().Context(), *userRecordID, *updatedUserRecord, readRecord)
			if err != nil {
				return contextAwareError(c, http.StatusInternalServerError, "Error writing to record store")
			}
		}

		serializedResponse, err := cbor.Marshal(response)
		if err != nil {
			return contextAwareError(c, http.StatusInternalServerError, "Error marshalling response payload")
		}

		otel.IncrementInt64Counter(
			c.Request().Context(),
			"realm.request.count",
			attribute.String("tenant", *tenantID),
			attribute.String("type", reflect.TypeOf(request.Payload).Name()),
		)

		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEOctetStream)
		return c.Blob(http.StatusOK, echo.MIMEOctetStream, serializedResponse)
	}, echojwt.WithConfig(echojwt.Config{
		KeyFunc: func(t *jwt.Token) (interface{}, error) {
			return secrets.GetJWTSigningKey(context.TODO(), provider.SecretsManager, t)
		},
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return &jwt.RegisteredClaims{}
		},
	}))

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
}

func userRecordID(c echo.Context, realmID uuid.UUID) (*records.UserRecordID, *string, error) {
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return nil, nil, errors.New("user is not a jwt token")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, nil, errors.New("jwt claims of unexpected type")
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != strings.ReplaceAll(realmID.String(), "-", "") {
		return nil, nil, errors.New("jwt claims contains invalid 'aud' field")
	}

	if claims.Subject == "" {
		return nil, nil, errors.New("jwt claims missing 'sub' field")
	}
	userID := claims.Subject

	if claims.Issuer == "" {
		return nil, nil, errors.New("jwt claims missing 'iss' field")
	}
	tenantName := claims.Issuer

	signingTenantName, _, err := secrets.ParseKid(token)
	if err != nil {
		return nil, nil, err
	}

	if *signingTenantName != tenantName {
		return nil, nil, errors.New("jwt 'iss' field does not match signer")
	}

	userRecordID, err := records.CreateUserRecordID(tenantName, userID)
	if err != nil {
		return nil, nil, err
	}

	return &userRecordID, &tenantName, nil
}

func handleRequest(c echo.Context, tenantID string, record records.UserRecord, request requests.SecretsRequest) (*responses.SecretsResponse, *records.UserRecord, error) {
	_, span := otel.StartSpan(c.Request().Context(), reflect.TypeOf(request.Payload).Name())
	defer span.End()
	span.SetAttributes(attribute.String("tenant", tenantID))

	switch payload := request.Payload.(type) {
	case requests.Register1:
		return &responses.SecretsResponse{
			Status:  responses.Ok,
			Payload: responses.Register1{},
		}, nil, nil
	case requests.Register2:
		record.RegistrationState = records.Registered{
			Version:                   payload.Version,
			OprfPrivateKey:            payload.OprfPrivateKey,
			OprfSignedPublicKey:       payload.OprfSignedPublicKey,
			UnlockKeyCommitment:       payload.UnlockKeyCommitment,
			UnlockKeyTag:              payload.UnlockKeyTag,
			EncryptionKeyScalarShare:  payload.EncryptionKeyScalarShare,
			EncryptedSecret:           payload.EncryptedSecret,
			EncryptedSecretCommitment: payload.EncryptedSecretCommitment,
			GuessCount:                0,
			Policy:                    payload.Policy,
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
					Version: state.Version,
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
			if state.Version != payload.Version {
				return &responses.SecretsResponse{
					Status:  responses.VersionMismatch,
					Payload: responses.Recover2{},
				}, nil, nil
			}

			if state.GuessCount >= uint16(state.Policy.NumGuesses) {
				record.RegistrationState = records.NoGuesses{}
				return &responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover2{},
				}, &record, nil
			}

			state.GuessCount++
			record.RegistrationState = state

			oprfBlindedResult, oprfProof, err := voprf.BlindEvaluate(
				&state.OprfPrivateKey,
				&state.OprfSignedPublicKey.PublicKey,
				&payload.OprfBlindedInput,
				cryptoRand.Reader,
			)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return nil, &record, err
			}

			return &responses.SecretsResponse{
				Status: responses.Ok,
				Payload: responses.Recover2{
					OprfSignedPublicKey: state.OprfSignedPublicKey,
					OprfBlindedResult:   *oprfBlindedResult,
					OprfProof:           *oprfProof,
					UnlockKeyCommitment: state.UnlockKeyCommitment,
					NumGuesses:          state.Policy.NumGuesses,
					GuessCount:          state.GuessCount,
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
			if state.Version != payload.Version {
				return &responses.SecretsResponse{
					Status:  responses.VersionMismatch,
					Payload: responses.Recover3{},
				}, nil, nil
			}

			guessesRemaining := state.Policy.NumGuesses - state.GuessCount

			if payload.UnlockKeyTag.ConstantTimeCompare(state.UnlockKeyTag) != 1 {
				if guessesRemaining == 0 {
					record.RegistrationState = records.NoGuesses{}
				}

				return &responses.SecretsResponse{
					Status: responses.BadUnlockKeyTag,
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
					EncryptionKeyScalarShare:  &state.EncryptionKeyScalarShare,
					EncryptedSecret:           &state.EncryptedSecret,
					EncryptedSecretCommitment: &state.EncryptedSecretCommitment,
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

	return nil, nil, errors.New("unexpected request type")
}

func contextAwareError(c echo.Context, code int, str string) error {
	select {
	case <-c.Request().Context().Done():
		// for ease of monitoring, use 499 (client closed request)
		// rather than 400 or 500 when the request was canceled.
		return c.String(499, "Client closed request")
	default:
		return c.String(code, str)
	}
}
