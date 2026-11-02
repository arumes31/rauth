package requestevent

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestDecisionDropsSecretsBeforePersistence(t *testing.T) {
	e := Decision(Event{URL: "https://name:password@example.com/document?token=secret#fragment", Source: "::ffff:192.0.2.1", Country: "US", Action: "authenticated", Status: 200, Time: time.Now()})
	require.Equal(t, "https://example.com/document", e.URL)
	require.Equal(t, "192.0.2.1", e.Source)
	e.EventID = uuid.NewString()
	e.NodeID = uuid.NewString()
	e.NodeName = "node"
	require.NoError(t, Validate(e, time.Now()))
	e.URL += "?password=secret"
	require.Error(t, Validate(e, time.Now()))
}
func TestEventRejectsIdentityTimeAndUnboundedLoss(t *testing.T) {
	base := Event{EventID: uuid.NewString(), NodeID: uuid.NewString(), NodeName: "node", Kind: "gap", Reason: "queue_overflow", Dropped: 1, Time: time.Now()}
	require.NoError(t, Validate(base, time.Now()))
	for _, change := range []func(*Event){func(e *Event) { e.EventID = "not-an-id" }, func(e *Event) { e.Time = time.Now().Add(-49 * time.Hour) }, func(e *Event) { e.Time = time.Now().Add(3 * time.Minute) }, func(e *Event) { e.Dropped = 1 << 63 }, func(e *Event) { e.Source = "credential" }, func(e *Event) { e.NodeName = strings.Repeat("x", 65) }} {
		event := base
		change(&event)
		require.Error(t, Validate(event, time.Now()))
	}
}
