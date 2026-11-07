package handlers

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"rauth/internal/core"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"github.com/redis/go-redis/v9"
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

// Fail the country write only: the session and generation reads still succeed.
type failingCountryWriteHook struct{ enabled atomic.Bool }

func (h *failingCountryWriteHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *failingCountryWriteHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		if h.enabled.Load() && cmd.Name() == "hset" && len(args) > 2 && args[1] == "X-rauth-authtoken=feed-session" && args[2] == "country" {
			return errors.New("simulated private country write failure")
		}
		return next(ctx, cmd)
	}
}
func (h *failingCountryWriteHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestAdminStreamMiddlewareCountryWriteFailureIsRetryable(t *testing.T) {
	for _, stream := range []string{"feed", "stats", "validate"} {
		t.Run(stream, func(t *testing.T) {
			setupHandlersTest(t)
			var cfg *core.Config
			srv, cookie := feedTestServerWithEvents(t, &statsFixture{}, func(h *AdminHandler) {
				h.Cfg.GeoChangeMode = "lenient"
				h.Cfg.RateLimitValidateMax = 100
				h.Cfg.RateLimitValidateDecay = 60
				cfg = h.Cfg
			})
			if stream == "validate" {
				srv.Config.Handler.(*echo.Echo).GET("/rauthvalidate", (&AuthHandler{Cfg: cfg}).Validate)
			}
			require.NoError(t, core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=feed-session", "country", "AT").Err())
			hook := &failingCountryWriteHook{}
			hook.enabled.Store(true)
			core.TokenDB.AddHook(hook)
			open := func() *http.Response {
				if stream == "feed" {
					return openFeed(t, srv, cookie, "")
				}
				if stream == "validate" {
					req, err := http.NewRequest(http.MethodGet, srv.URL+"/rauthvalidate", nil)
					require.NoError(t, err)
					req.AddCookie(cookie)
					response, err := (&http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
					require.NoError(t, err)
					t.Cleanup(func() { _ = response.Body.Close() })
					return response
				}
				return statsGet(t, srv.URL, "stream?range=5m", cookie)
			}
			failed := open()
			require.Equal(t, http.StatusServiceUnavailable, failed.StatusCode)
			require.Empty(t, failed.Header.Get("Location"))
			require.Empty(t, failed.Header.Get("X-RAuth-User"))
			body, err := io.ReadAll(failed.Body)
			require.NoError(t, err)
			require.NotContains(t, string(body), "simulated private country write failure")
			require.NoError(t, failed.Body.Close())
			hook.enabled.Store(false)
			recovered := open()
			require.Equal(t, http.StatusOK, recovered.StatusCode)
			if stream == "validate" {
				require.Equal(t, "feedadmin", recovered.Header.Get("X-RAuth-User"))
				require.NoError(t, recovered.Body.Close())
				return
			}
			kind, _, _ := readFeedEvent(t, bufio.NewReader(recovered.Body))
			if stream == "feed" {
				require.Equal(t, "ready", kind)
			} else {
				require.Equal(t, "stats", kind)
			}
			require.NoError(t, recovered.Body.Close())
		})
	}
}
