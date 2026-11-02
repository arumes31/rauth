package handlers

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"rauth/internal/core"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestAdminStreamsRetryAuthorityFailureWithoutEndingSession(t *testing.T) {
	for _, stream := range []string{"feed", "stats"} {
		for _, backend := range []string{"sessions", "accounts"} {
			t.Run(stream+"/"+backend, func(t *testing.T) {
				setupHandlersTest(t)
				srv, cookie := feedTestServerWithEvents(t, &statsFixture{})
				original := core.PG
				if backend == "accounts" {
					isolated, err := pgxpool.NewWithConfig(context.Background(), original.Config())
					require.NoError(t, err)
					core.PG = isolated
					t.Cleanup(func() { core.PG = original; isolated.Close() })
				}
				open := func() *http.Response {
					if stream == "feed" {
						return openFeed(t, srv, cookie, "")
					}
					return statsGet(t, srv.URL, "stream?range=5m", cookie)
				}
				response := open()
				require.Equal(t, http.StatusOK, response.StatusCode)
				reader := bufio.NewReader(response.Body)
				kind, _, _ := readFeedEvent(t, reader)
				expected := "ready"
				if stream == "stats" {
					expected = "stats"
				}
				require.Equal(t, expected, kind)
				if backend == "sessions" {
					sharedMiniredis.SetError("ERR simulated authority interruption")
					t.Cleanup(func() { sharedMiniredis.SetError("") })
				} else {
					core.PG.Close()
				}
				tail, err := io.ReadAll(reader)
				require.NoError(t, err, "stream must close within the client deadline")
				require.NotContains(t, string(tail), "session-ended", "an outage must not permanently disable browser reconnection")
				require.NoError(t, response.Body.Close())
				// A recovered authority accepts the original cookie without another login.
				if backend == "sessions" {
					sharedMiniredis.SetError("")
				} else {
					core.PG = original
				}
				recovered := open()
				require.Equal(t, http.StatusOK, recovered.StatusCode)
				kind, _, _ = readFeedEvent(t, bufio.NewReader(recovered.Body))
				require.Equal(t, expected, kind)
				require.NoError(t, recovered.Body.Close())
			})
		}
	}
}

func TestFeedSessionAuthorityErrorsAreNotForbidden(t *testing.T) {
	setupHandlersTest(t)
	srv, cookie := feedTestServerWithEvents(t, &statsFixture{})
	sharedMiniredis.SetError("ERR temporary authority outage")
	t.Cleanup(func() { sharedMiniredis.SetError("") })
	response := openFeed(t, srv, cookie, "")
	require.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(data), "ERR temporary authority outage"))
}
