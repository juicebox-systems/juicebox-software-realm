package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/otel"
	"github.com/juicebox-systems/juicebox-software-realm/pubsub"
	"github.com/juicebox-systems/juicebox-software-realm/requests"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/secrets"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func NewTenantAPIServer(
	realmID types.RealmID,
	secretsManager secrets.SecretsManager,
	pubSub pubsub.PubSub,
) *echo.Echo {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(otelecho.Middleware("echo-router"))

	AddTenantLogHandlers(e, realmID, pubSub, secretsManager, "tenant-")
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{"realmID": realmID.String()})
	})
	return e
}

func AddTenantLogHandlers(e *echo.Echo, realmID types.RealmID, pubsub pubsub.PubSub, secretsManager secrets.SecretsManager, secretsPrefix string) {
	jwtConfig := echojwt.Config{
		KeyFunc: func(t *jwt.Token) (interface{}, error) {
			return secrets.GetJWTSigningKeyWithPrefix(context.TODO(), secretsManager, secretsPrefix, t)
		},
		NewClaimsFunc: func(_ echo.Context) jwt.Claims {
			return &claims{}
		},
	}
	e.POST("/tenant_log", func(c echo.Context) error {
		ctx, span := otel.StartSpan(c.Request().Context(), "tenant_log")
		defer span.End()

		result, err := handleTenantLogRequest(ctx, c, realmID, span, pubsub)
		if err != nil {
			return types.NewHTTPError(http.StatusInternalServerError, err).ToEcho()
		}
		return c.JSON(200, result)

	}, middleware.BodyLimit("32K"), echojwt.WithConfig(jwtConfig))

	e.POST("/tenant_log/ack", func(c echo.Context) error {
		ctx, span := otel.StartSpan(c.Request().Context(), "ack")
		defer span.End()

		result, err := handleTenantLogAckRequest(ctx, c, realmID, span, pubsub)
		if err != nil {
			return types.NewHTTPError(http.StatusInternalServerError, err).ToEcho()
		}
		return c.JSON(200, result)

	}, middleware.BodyLimit("32K"), echojwt.WithConfig(jwtConfig))
}

func handleTenantLogRequest(ctx context.Context, c echo.Context, realmID types.RealmID, span trace.Span, pubsub pubsub.PubSub) (*responses.TenantLog, error) {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return nil, types.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error reading request body: %w", err))
	}

	claims, err := verifyToken(c, realmID, requireScope, scopeAudit)
	if err != nil {
		return nil, types.NewHTTPError(http.StatusUnauthorized, err)
	}

	var request requests.TenantLog
	err = json.Unmarshal(body, &request)
	if err != nil {
		return nil, types.NewHTTPError(http.StatusBadRequest, fmt.Errorf("error unmarshalling request body: %w", err))
	}
	if request.PageSize < 1 {
		request.PageSize = 1
	} else if request.PageSize > 200 {
		request.PageSize = 200
	}
	span.SetAttributes(attribute.Int("ack_count", len(request.Acks)), attribute.Int("page_size", int(request.PageSize)))

	if len(request.Acks) > 0 {
		if pubsub.Ack(ctx, realmID, claims.Issuer, request.Acks) != nil {
			return nil, types.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error ack'ing events: %w", err))
		}
	}

	entries, err := pubsub.Pull(ctx, realmID, claims.Issuer, uint16(request.PageSize))
	if err != nil {
		return nil, types.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error pulling new messages: %w", err))
	}
	span.SetAttributes(attribute.Int("event_count", len(entries)))

	otel.IncrementInt64Counter(
		ctx,
		"realm.tenant_log.count",
		attribute.String("tenant", claims.Issuer),
		attribute.String("type", c.Request().URL.Path),
	)
	if entries == nil {
		entries = []responses.TenantLogEntry{}
	}
	return &responses.TenantLog{Events: entries}, nil
}

func handleTenantLogAckRequest(ctx context.Context, c echo.Context, realmID types.RealmID, span trace.Span, pubsub pubsub.PubSub) (*responses.TenantLogAck, error) {
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return nil, types.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error reading request body: %w", err))
	}

	claims, err := verifyToken(c, realmID, true, scopeAudit)
	if err != nil {
		return nil, types.NewHTTPError(http.StatusUnauthorized, err)
	}

	var request requests.TenantLogAck
	err = json.Unmarshal(body, &request)
	if err != nil {
		return nil, types.NewHTTPError(http.StatusBadRequest, fmt.Errorf("error unmarshalling request body: %w", err))
	}
	if len(request.Acks) > 0 {
		if err := pubsub.Ack(ctx, realmID, claims.Issuer, request.Acks); err != nil {
			return nil, types.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error ack'ing events: %w", err))
		}
	}
	span.SetAttributes(attribute.Int("ack_count", len(request.Acks)))
	otel.IncrementInt64Counter(
		ctx,
		"realm.tenant_log.count",
		attribute.String("tenant", claims.Issuer),
		attribute.String("type", c.Request().URL.Path),
	)
	return &responses.TenantLogAck{}, nil
}
