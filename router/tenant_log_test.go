package router

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicebox-systems/juicebox-software-realm/pubsub"
	"github.com/juicebox-systems/juicebox-software-realm/requests"
	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/secrets"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	"github.com/stretchr/testify/assert"
)

func TestTenantLogApi(t *testing.T) {
	realmID := types.RealmID(makeRepeatingByteArray(250, 16))
	os.Setenv("TENANT_SECRETS", `{"acme":{"1":"acme-tenant-key"}}`)
	sm, err := secrets.NewMemorySecretsManagerWithPrefix(context.Background(), "tenant-")
	assert.NoError(t, err)
	ps := pubsub.NewMemPubSub()
	e := NewTenantAPIServer(realmID, sm, ps)
	go func() {
		e.Start(":7899")
	}()
	defer e.Close()
	n := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "acme",
			Subject:   "presso",
			Audience:  []string{realmID.String()},
			ExpiresAt: jwt.NewNumericDate(n.Add(time.Minute * 30)),
			NotBefore: jwt.NewNumericDate(n.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(n),
		},
		Scope: "audit",
	})
	token.Header["kid"] = "acme:1"
	bearer, err := token.SignedString([]byte("acme-tenant-key"))
	assert.NoError(t, err)

	res := pollTenantLog(t, bearer, nil, 1)
	assert.Equal(t, 0, len(res.Events))
	assert.NotNil(t, res.Events)

	assert.NoError(t, ps.Publish(context.Background(), realmID, "acme", pubsub.EventMessage{
		User:  "presso",
		Event: "registered",
	}))
	assert.NoError(t, ps.Publish(context.Background(), realmID, "acme", pubsub.EventMessage{
		User:  "presso",
		Event: "deleted",
	}))
	assert.NoError(t, ps.Publish(context.Background(), realmID, "acme", pubsub.EventMessage{
		User:  "apollo",
		Event: "registered",
	}))

	msgs := pollTenantLog(t, bearer, nil, 1)
	assert.Equal(t, 1, len(msgs.Events))
	assert.Equal(t, "presso", msgs.Events[0].UserID)
	assert.Equal(t, "registered", msgs.Events[0].Event)
	assert.True(t, len(msgs.Events[0].ID) > 0)
	assert.True(t, len(msgs.Events[0].Ack) > 0)

	// We can ack the message we just read, and read some more in one shot.
	msgs = pollTenantLog(t, bearer, []string{msgs.Events[0].Ack}, 2)
	assert.Equal(t, 2, len(msgs.Events))
	assert.Equal(t, "presso", msgs.Events[0].UserID)
	assert.Equal(t, "deleted", msgs.Events[0].Event)
	assert.Equal(t, "apollo", msgs.Events[1].UserID)
	assert.Equal(t, "registered", msgs.Events[1].Event)

	// We can separately ack a message, doesn't have to be in order.
	ackTenantLog(t, bearer, []string{msgs.Events[1].Ack})

	// Unack'd messages still appear
	msgs = pollTenantLog(t, bearer, nil, 2)
	assert.Equal(t, 1, len(msgs.Events))
	assert.Equal(t, "presso", msgs.Events[0].UserID)
	assert.Equal(t, "deleted", msgs.Events[0].Event)

	// Missing audit scope
	n = time.Now()
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, &claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "acme",
			Subject:   "presso",
			Audience:  []string{realmID.String()},
			ExpiresAt: jwt.NewNumericDate(n.Add(time.Minute * 30)),
			NotBefore: jwt.NewNumericDate(n.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(n),
		},
		Scope: "",
	})
	token.Header["kid"] = "acme:1"
	bearer, err = token.SignedString([]byte("acme-tenant-key"))
	assert.NoError(t, err)
	sc, body := tenantLogRequest(t, bearer, "/tenant_log", requests.TenantLog{})
	assert.Equal(t, http.StatusUnauthorized, sc)
	assert.Equal(t, "{\"message\":\"jwt claims missing 'scope' field\"}\n", string(body))
}

func pollTenantLog(t *testing.T, authToken string, acks []string, pageSize int16) responses.TenantLog {
	reqBody := requests.TenantLog{
		Acks:     acks,
		PageSize: pageSize,
	}
	sc, res := tenantLogRequest(t, authToken, "/tenant_log", reqBody)
	assert.Equal(t, 200, sc)
	msgs := responses.TenantLog{}
	assert.NoError(t, json.Unmarshal(res, &msgs))
	return msgs
}

func ackTenantLog(t *testing.T, authToken string, acks []string) {
	reqBody := requests.TenantLogAck{
		Acks: acks,
	}
	sc, res := tenantLogRequest(t, authToken, "/tenant_log/ack", reqBody)
	assert.Equal(t, 200, sc)
	msgs := responses.TenantLogAck{}
	assert.NoError(t, json.Unmarshal(res, &msgs))
}

func tenantLogRequest(t *testing.T, authToken string, path string, reqBody interface{}) (int, []byte) {
	reqBodyBytes := []byte{}
	var err error
	if reqBody != nil {
		reqBodyBytes, err = json.Marshal(reqBody)
		assert.NoError(t, err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:7899"+path, bytes.NewReader(reqBodyBytes))
	assert.NoError(t, err)
	req.Header.Add("Authorization", "Bearer "+authToken)
	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	b, err := io.ReadAll(res.Body)
	assert.NoError(t, err)
	return res.StatusCode, b
}

func TestEventUserId(t *testing.T) {
	regClaims := jwt.RegisteredClaims{Issuer: "test", Subject: "121314"}
	id := eventUserID(&claims{
		RegisteredClaims: regClaims,
	})
	assert.Equal(t, id, "447ddec5f08c757d40e7acb9f1bc10ed44a960683bb991f5e4ed17498f786ff8")
}
