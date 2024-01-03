package router

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/oprf"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/providers"
	"github.com/juicebox-systems/juicebox-software-realm/pubsub"
	"github.com/juicebox-systems/juicebox-software-realm/records"
	"github.com/juicebox-systems/juicebox-software-realm/requests"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/secrets"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var Version = semver.MustParse("0.2.0")

func RunRouter(
	realmID types.RealmID,
	provider *providers.Provider,
	port uint64,
) {
	e := echo.New()
	e.HideBanner = true
	e.Server.IdleTimeout = 11 * 60 * time.Second

	e.Use(timingHeader)
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(otelecho.Middleware("echo-router"))

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{"realmID": realmID.String()})
	})

	e.POST("/req", func(c echo.Context) error {
		sdkVersion, err := semver.NewVersion(c.Request().Header.Get("X-Juicebox-Version"))
		hasValidVersion := err == nil && (sdkVersion.Major() > Version.Major() || sdkVersion.Major() == Version.Major() && sdkVersion.Minor() >= Version.Minor())
		if !hasValidVersion {
			return contextAwareError(c, http.StatusUpgradeRequired, "SDK upgrade required")
		}

		userRecordID, claims, err := userRecordID(c, realmID)
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

		result, err := handleRequest(c, claims, userRecord, request, cryptoRand.Reader)
		if err != nil {
			return contextAwareError(c, http.StatusBadRequest, "Error processing request")
		}

		if result.updatedRecord != nil {
			err := provider.RecordStore.WriteRecord(c.Request().Context(), *userRecordID, *result.updatedRecord, readRecord)
			if err != nil {
				return contextAwareError(c, http.StatusInternalServerError, "Error writing to record store")
			}
		}
		if result.event != nil {
			err := provider.PubSub.Publish(c.Request().Context(), realmID, claims.Issuer, *result.event)
			if err != nil {
				return contextAwareError(c, http.StatusInternalServerError, "Error writing to pub/sub queue")
			}
		}
		serializedResponse, err := cbor.Marshal(&result.response)
		if err != nil {
			return contextAwareError(c, http.StatusInternalServerError, "Error marshalling response payload")
		}

		otel.IncrementInt64Counter(
			c.Request().Context(),
			"realm.request.count",
			attribute.String("tenant", claims.Issuer),
			attribute.String("type", reflect.TypeOf(request.Payload).Name()),
		)

		c.Response().Header().Set(echo.HeaderContentType, echo.MIMEOctetStream)
		return c.Blob(http.StatusOK, echo.MIMEOctetStream, serializedResponse)

	}, middleware.BodyLimit("2K"), echojwt.WithConfig(echojwt.Config{
		KeyFunc: func(t *jwt.Token) (interface{}, error) {
			return secrets.GetJWTSigningKey(context.TODO(), provider.SecretsManager, t)
		},
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return &claims{}
		},
	}))

	AddTenantLogHandlers(e, realmID, provider.PubSub, provider.SecretsManager, types.JuiceboxTenantSecretPrefix)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
}

type appResult struct {
	response      responses.SecretsResponse
	updatedRecord *records.UserRecord
	event         *pubsub.EventMessage
}

func handleRequest(c echo.Context, claims *claims, record records.UserRecord, request requests.SecretsRequest, cryptoRng io.Reader) (*appResult, error) {
	_, span := otel.StartSpan(c.Request().Context(), reflect.TypeOf(request.Payload).Name())
	defer span.End()
	span.SetAttributes(attribute.String("tenant", claims.Issuer))

	switch payload := request.Payload.(type) {
	case requests.Register1:
		return &appResult{
			response: responses.SecretsResponse{
				Status:  responses.Ok,
				Payload: responses.Register1{},
			}}, nil
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
		return &appResult{
			response: responses.SecretsResponse{
				Status:  responses.Ok,
				Payload: responses.Register2{},
			},
			updatedRecord: &record,
			event: &pubsub.EventMessage{
				User:  eventUserID(claims),
				Event: "registered",
			}}, nil
	case requests.Recover1:
		switch state := record.RegistrationState.(type) {
		case records.Registered:
			if state.GuessCount >= uint16(state.Policy.NumGuesses) {
				record.RegistrationState = records.NoGuesses{}
				return &appResult{
					response: responses.SecretsResponse{
						Status:  responses.NoGuesses,
						Payload: responses.Recover1{},
					},
					updatedRecord: &record,
				}, nil
			}

			return &appResult{
				response: responses.SecretsResponse{
					Status: responses.Ok,
					Payload: responses.Recover1{
						Version: state.Version,
					},
				}}, nil
		case records.NoGuesses:
			return &appResult{
				response: responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover1{},
				}}, nil
		case records.NotRegistered:
			return &appResult{
				response: responses.SecretsResponse{
					Status:  responses.NotRegistered,
					Payload: responses.Recover1{},
				}}, nil
		}
	case requests.Recover2:
		switch state := record.RegistrationState.(type) {
		case records.Registered:
			if state.Version != payload.Version {
				return &appResult{
					response: responses.SecretsResponse{
						Status:  responses.VersionMismatch,
						Payload: responses.Recover2{},
					}}, nil
			}

			if state.GuessCount >= uint16(state.Policy.NumGuesses) {
				record.RegistrationState = records.NoGuesses{}
				return &appResult{
					response: responses.SecretsResponse{
						Status:  responses.NoGuesses,
						Payload: responses.Recover2{},
					},
					updatedRecord: &record,
				}, nil
			}

			state.GuessCount++
			record.RegistrationState = state

			oprfBlindedResult, oprfProof, err := oprf.BlindEvaluate(
				&state.OprfPrivateKey,
				&state.OprfSignedPublicKey.PublicKey,
				&payload.OprfBlindedInput,
				cryptoRng,
			)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			return &appResult{
				response: responses.SecretsResponse{
					Status: responses.Ok,
					Payload: responses.Recover2{
						OprfSignedPublicKey: state.OprfSignedPublicKey,
						OprfBlindedResult:   *oprfBlindedResult,
						OprfProof:           *oprfProof,
						UnlockKeyCommitment: state.UnlockKeyCommitment,
						NumGuesses:          state.Policy.NumGuesses,
						GuessCount:          state.GuessCount,
					},
				},
				updatedRecord: &record,
				event: &pubsub.EventMessage{
					User:       eventUserID(claims),
					Event:      "guess_used",
					NumGuesses: &state.Policy.NumGuesses,
					GuessCount: &state.GuessCount,
				}}, nil
		case records.NoGuesses:
			return &appResult{
				response: responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover2{},
				}}, nil
		case records.NotRegistered:
			return &appResult{
				response: responses.SecretsResponse{
					Status:  responses.NotRegistered,
					Payload: responses.Recover2{},
				}}, nil
		}
	case requests.Recover3:
		switch state := record.RegistrationState.(type) {
		case records.Registered:
			if state.Version != payload.Version {
				return &appResult{
					response: responses.SecretsResponse{
						Status:  responses.VersionMismatch,
						Payload: responses.Recover3{},
					}}, nil
			}

			guessesRemaining := state.Policy.NumGuesses - state.GuessCount

			if payload.UnlockKeyTag.ConstantTimeCompare(state.UnlockKeyTag) != 1 {
				if guessesRemaining == 0 {
					record.RegistrationState = records.NoGuesses{}
				}

				return &appResult{
					response: responses.SecretsResponse{
						Status: responses.BadUnlockKeyTag,
						Payload: responses.Recover3{
							GuessesRemaining: &guessesRemaining,
						},
					},
					updatedRecord: &record,
				}, nil
			}

			state.GuessCount = 0
			record.RegistrationState = state

			return &appResult{
				response: responses.SecretsResponse{
					Status: responses.Ok,
					Payload: responses.Recover3{
						EncryptionKeyScalarShare:  &state.EncryptionKeyScalarShare,
						EncryptedSecret:           &state.EncryptedSecret,
						EncryptedSecretCommitment: &state.EncryptedSecretCommitment,
					},
				},
				updatedRecord: &record,
				event: &pubsub.EventMessage{
					User:  eventUserID(claims),
					Event: "share_recovered",
				}}, nil
		case records.NoGuesses:
			return &appResult{
				response: responses.SecretsResponse{
					Status:  responses.NoGuesses,
					Payload: responses.Recover3{},
				}}, nil
		case records.NotRegistered:
			return &appResult{
				response: responses.SecretsResponse{
					Status:  responses.NotRegistered,
					Payload: responses.Recover3{},
				}}, nil
		}
	case requests.Delete:
		record.RegistrationState = records.NotRegistered{}
		return &appResult{
			response: responses.SecretsResponse{
				Status:  responses.Ok,
				Payload: responses.Delete{},
			},
			updatedRecord: &record,
			event: &pubsub.EventMessage{
				User:  eventUserID(claims),
				Event: "deleted",
			},
		}, nil
	}

	return nil, errors.New("unexpected request type")
}

// Builds the hashed tenant & userID string that is included in the tenant event log entries.
func eventUserID(c *claims) string {
	h := sha256.New()
	h.Write([]byte(c.Issuer))
	h.Write([]byte{':'})
	h.Write([]byte(c.Subject))
	return hex.EncodeToString(h.Sum(nil))
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

func timingHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		c.Response().Before(func() {
			nanos := time.Since(start).Nanoseconds()
			c.Response().Header().Add("x-exec-time", strconv.FormatInt(nanos, 10))
		})
		return next(c)
	}
}
