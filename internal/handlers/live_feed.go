package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"rauth/internal/authstate"
	"rauth/internal/core"
	"rauth/internal/eventstore"
	"rauth/internal/requestevent"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
)

const liveFeedAuthInterval = 5 * time.Second
const liveFeedWriteTimeout = 10 * time.Second

var liveFeedStreams = struct {
	sync.Mutex
	users map[string]int
	total int
}{users: make(map[string]int)}

func acquireFeedStream(user string) bool {
	liveFeedStreams.Lock()
	defer liveFeedStreams.Unlock()
	if liveFeedStreams.total >= 16 || liveFeedStreams.users[user] >= 3 {
		return false
	}
	liveFeedStreams.total++
	liveFeedStreams.users[user]++
	return true
}

func releaseFeedStream(user string) {
	liveFeedStreams.Lock()
	defer liveFeedStreams.Unlock()
	liveFeedStreams.total--
	liveFeedStreams.users[user]--
	if liveFeedStreams.users[user] == 0 {
		delete(liveFeedStreams.users, user)
	}
}

func feedCursor(raw string) (string, uint64, bool) {
	if len(raw) > 128 {
		return "", 0, false
	}
	epoch, seq, ok := strings.Cut(raw, ":")
	if !ok || epoch == "" || seq == "" {
		return "", 0, false
	}
	cursor, err := strconv.ParseUint(seq, 10, 64)
	return epoch, cursor, err == nil
}

func (h *AdminHandler) feedSessionValid(c *echo.Context, user, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 3*time.Second)
	defer cancel()
	data, err := core.ReadAuthSession(ctx, token)
	if errors.Is(err, authstate.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !core.SessionAudienceValid(data, "") || data["status"] != "valid" || data["username"] != user {
		return false, nil
	}
	valid, err := core.SessionAuthorization(ctx, data)
	if err != nil || !valid {
		return false, err
	}
	req := c.Request().WithContext(ctx)
	valid, err = core.SessionBindingAuthorization(h.Cfg, req, token, "X-rauth-authtoken="+token, data, c.RealIP())
	if err != nil || !valid {
		return false, err
	}
	return core.UserIsAdminContext(ctx, user)
}

// LiveFeed streams only operational request metadata. The route is also
// protected by AuthMiddleware and AdminMiddleware; ongoing access is rechecked
// so revocations and demotions do not leave a long-lived privileged stream.
func (h *AdminHandler) LiveFeed(c *echo.Context) error {
	user, _ := c.Get("username").(string)
	token, _ := c.Get("token").(string)
	if user == "" || token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}
	if valid, err := h.feedSessionValid(c, user, token); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Authorization temporarily unavailable")
	} else if !valid {
		return echo.NewHTTPError(http.StatusForbidden, http.StatusText(http.StatusForbidden))
	}
	if _, ok := c.Response().(http.Flusher); !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
	if !acquireFeedStream(user) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many live-feed connections")
	}
	defer releaseFeedStream(user)

	feed := core.LiveRequests
	node := c.QueryParam("node")
	if node != "" && (!requestevent.ValidID(node) || h.RequestEvents == nil) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid processing node")
	}
	read := func(cursor uint64) (eventstore.Batch, error) {
		if h.RequestEvents != nil {
			ctx, cancel := context.WithTimeout(c.Request().Context(), eventstore.ReadTimeout)
			defer cancel()
			return h.RequestEvents.After(ctx, cursor, node)
		}
		memory := feed.After(cursor)
		out := eventstore.Batch{Events: memory.Events, Oldest: memory.Oldest, Latest: memory.Latest, Next: memory.Latest, Changed: memory.Changed}
		if len(memory.Events) == core.RequestFeedBatch {
			out.Next = memory.Events[len(memory.Events)-1].ID
		}
		return out, nil
	}
	batch, readErr := read(0)
	if readErr != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Request history unavailable")
	}
	epoch := feed.Epoch()
	if h.RequestEvents != nil {
		epoch = h.RequestEvents.Epoch()
		if epoch == "" {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Request history unavailable")
		}
	}
	cursor := uint64(0)
	raw := c.Request().Header.Get("Last-Event-ID")
	if raw == "" {
		raw = c.QueryParam("after")
	}
	reset := false
	if raw != "" {
		cursorEpoch, n, ok := feedCursor(raw)
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid feed cursor")
		}
		if cursorEpoch != epoch || n > batch.Latest {
			reset = true
		} else {
			cursor = n
		}
	}
	tail, hasTail := h.RequestEvents.(interface {
		FeedStart(context.Context, string, int) (uint64, error)
	})
	startFor := func(limit int) (uint64, error) {
		ctx, cancel := context.WithTimeout(c.Request().Context(), eventstore.ReadTimeout)
		defer cancel()
		return tail.FeedStart(ctx, node, limit)
	}
	if raw == "" || reset {
		if hasTail {
			cursor, readErr = startFor(core.RequestFeedBatch)
			if readErr != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Request history unavailable")
			}
		} else if batch.Latest > core.RequestFeedBatch {
			cursor = batch.Latest - core.RequestFeedBatch
		}
	}
	replayLimited := false
	const maxReplay = 1000
	if h.RequestEvents != nil {
		minimum := uint64(0)
		if hasTail {
			minimum, readErr = startFor(maxReplay)
			if readErr != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Request history unavailable")
			}
		} else if batch.Latest > maxReplay {
			minimum = batch.Latest - maxReplay
		}
		if cursor < minimum {
			cursor = minimum
			replayLimited = true
		}
	}
	// Cold history/tail lookups may outlive a revocation. Recheck before
	// committing headers or disclosing any retained request metadata.
	if valid, err := h.feedSessionValid(c, user, token); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Authorization temporarily unavailable")
	} else if !valid {
		return echo.NewHTTPError(http.StatusForbidden, http.StatusText(http.StatusForbidden))
	}
	lastAuth := time.Now()
	hdr := c.Response().Header()
	hdr.Set(echo.HeaderContentType, "text/event-stream")
	hdr.Set(echo.HeaderCacheControl, "no-store")
	hdr.Set("X-Accel-Buffering", "no")
	c.Response().WriteHeader(http.StatusOK)
	controller := http.NewResponseController(c.Response())
	write := func(kind, id string, data any) error {
		if err := controller.SetWriteDeadline(time.Now().Add(liveFeedWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		payload, err := json.Marshal(data)
		if err != nil {
			return err
		}
		if id != "" {
			if _, err = fmt.Fprintf(c.Response(), "id: %s\n", id); err != nil {
				return err
			}
		}
		if _, err = fmt.Fprintf(c.Response(), "event: %s\ndata: %s\n\n", kind, payload); err != nil {
			return err
		}
		return controller.Flush()
	}
	state := map[string]string{"epoch": epoch, "cursor": fmt.Sprintf("%s:%d", epoch, cursor)}
	if reset {
		if err := write("reset", "", state); err != nil {
			return nil
		}
	}
	if err := write("ready", "", state); err != nil {
		return nil
	}
	if replayLimited {
		if err := write("gap", "", map[string]any{"reason": "display_limited", "message": "Showing the newest retained decisions in the live feed"}); err != nil {
			return nil
		}
	}
	ticker := time.NewTicker(liveFeedAuthInterval)
	defer ticker.Stop()
	stillAuthorized := func(force bool) bool {
		if !force && time.Since(lastAuth) < liveFeedAuthInterval {
			return true
		}
		valid, err := h.feedSessionValid(c, user, token)
		if err != nil {
			// Close without a terminal event so the client retries.
			return false
		}
		if !valid {
			_ = write("session-ended", "", map[string]string{"message": "Session or administrator access ended"})
			return false
		}
		lastAuth = time.Now()
		return true
	}
	for {
		if c.Request().Context().Err() != nil {
			return nil
		}
		if !stillAuthorized(false) {
			return nil
		}
		batch, readErr = read(cursor)
		if readErr != nil {
			return nil
		}
		if raw != "" && batch.PrunedThrough > cursor {
			if err := write("gap", "", map[string]any{"reason": "history_expired", "message": "Older request history expired while disconnected"}); err != nil {
				return nil
			}
		}
		if batch.Oldest > 0 && cursor < batch.Oldest-1 {
			if h.RequestEvents == nil {
				if err := write("gap", "", map[string]uint64{"dropped": batch.Oldest - 1 - cursor}); err != nil {
					return nil
				}
			}
			cursor = batch.Oldest - 1
		}
		sentCursor := cursor
		for _, event := range batch.Events {
			if event.Kind == "telemetry" {
				cursor = event.ID
				continue
			}
			if !stillAuthorized(false) {
				return nil
			}
			kind := "request"
			if event.Kind == "gap" {
				kind = "gap"
			}
			if err := write(kind, fmt.Sprintf("%s:%d", epoch, event.ID), event); err != nil {
				return nil
			}
			cursor = event.ID
			sentCursor = cursor
		}
		if cursor < batch.Next {
			cursor = batch.Next
		}
		if cursor > sentCursor {
			if err := write("cursor", fmt.Sprintf("%s:%d", epoch, cursor), map[string]uint64{"latest": cursor}); err != nil {
				return nil
			}
		}
		if cursor < batch.Latest {
			continue
		}
		select {
		case <-c.Request().Context().Done():
			return nil
		case <-batch.Changed:
		case <-ticker.C:
			if !stillAuthorized(true) {
				return nil
			}
			if err := write("heartbeat", "", map[string]string{"time": time.Now().UTC().Format(time.RFC3339)}); err != nil {
				return nil
			}
		}
	}
}
