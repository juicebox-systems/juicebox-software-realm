package pubsub

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/juicebox-systems/juicebox-software-realm/responses"
	"github.com/juicebox-systems/juicebox-software-realm/types"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type memPubSub struct {
	lock   sync.Mutex
	events map[string][]responses.TenantLogEntry
	nextID int
}

func NewMemPubSub() PubSub {
	return &spannedPubSub{
		inner: &memPubSub{
			events: make(map[string][]responses.TenantLogEntry),
		},
		msgType: semconv.MessagingSystemKey.String("InMemory"),
	}
}

func key(realm types.RealmID, tenant string) string {
	return realm.String() + ":" + tenant
}

func (c *memPubSub) Ack(_ context.Context, realm types.RealmID, tenant string, acks []string) error {
	k := key(realm, tenant)
	c.lock.Lock()
	defer c.lock.Unlock()
	c.events[k] = slices.DeleteFunc(c.events[k], func(m responses.TenantLogEntry) bool {
		return slices.Contains(acks, m.Ack)
	})
	return nil
}

func (c *memPubSub) Publish(_ context.Context, realm types.RealmID, tenant string, msg EventMessage) error {
	k := key(realm, tenant)
	c.lock.Lock()
	defer c.lock.Unlock()
	e := responses.TenantLogEntry{
		ID:         fmt.Sprintf("%d", c.nextID),
		Ack:        fmt.Sprintf("%d_%x", c.nextID, c.nextID),
		When:       time.Now(),
		UserID:     msg.User,
		Event:      msg.Event,
		NumGuesses: msg.NumGuesses,
		GuessCount: msg.GuessCount,
	}
	c.nextID++
	c.events[k] = append(c.events[k], e)
	return nil
}

func (c *memPubSub) Pull(_ context.Context, realm types.RealmID, tenant string, max uint16) ([]responses.TenantLogEntry, error) {
	k := key(realm, tenant)
	c.lock.Lock()
	defer c.lock.Unlock()
	messages := c.events[k]
	max = min(max, uint16(len(messages)))
	results := append([]responses.TenantLogEntry{}, messages[:max]...)
	return results, nil
}
