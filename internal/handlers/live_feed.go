package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"rauth/internal/core"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
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

func (h *AdminHandler) feedSessionValid(c echo.Context, user, token string) bool {
	data, err := core.ReadAuthSession(c.Request().Context(), token)
	if err != nil || !core.SessionAudienceValid(data, "") || data["status"] != "valid" || data["username"] != user || !core.SessionAuthorized(data) {
		return false
	}
	if !core.SessionBindingValid(h.Cfg, c.Request(), token, "X-rauth-authtoken="+token, data, c.RealIP()) {
		return false
	}
	admin, err := core.UserIsAdmin(user)
	return err == nil && admin
}

// LiveFeed streams only operational request metadata. The route is also
// protected by AuthMiddleware and AdminMiddleware; ongoing access is rechecked
// so revocations and demotions do not leave a long-lived privileged stream.
func (h *AdminHandler) LiveFeed(c echo.Context) error {
	user, _ := c.Get("username").(string)
	token, _ := c.Get("token").(string)
	if user == "" || token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}
	if !h.feedSessionValid(c, user, token) {
		return echo.NewHTTPError(http.StatusForbidden)
	}
	if _, ok := c.Response().Writer.(http.Flusher); !ok {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	if !acquireFeedStream(user) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many live-feed connections")
	}
	defer releaseFeedStream(user)

	feed := core.LiveRequests
	batch := feed.After(0)
	cursor := uint64(0)
	raw := c.Request().Header.Get("Last-Event-ID")
	if raw == "" {
		raw = c.QueryParam("after")
	}
	reset := false
	if raw != "" {
		epoch, n, ok := feedCursor(raw)
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid feed cursor")
		}
		if epoch != feed.Epoch() || n > batch.Latest {
			reset = true
		} else {
			cursor = n
		}
	}
	if raw == "" || reset {
		if batch.Latest > core.RequestFeedBatch {
			cursor = batch.Latest - core.RequestFeedBatch
		}
	}
	hdr := c.Response().Header()
	hdr.Set(echo.HeaderContentType, "text/event-stream")
	hdr.Set(echo.HeaderCacheControl, "no-store")
	hdr.Set("X-Accel-Buffering", "no")
	c.Response().WriteHeader(http.StatusOK)
	controller := http.NewResponseController(c.Response().Writer)
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
	state := map[string]string{"epoch": feed.Epoch(), "cursor": fmt.Sprintf("%s:%d", feed.Epoch(), cursor)}
	if reset {
		if err := write("reset", "", state); err != nil {
			return nil
		}
	}
	if err := write("ready", "", state); err != nil {
		return nil
	}
	ticker := time.NewTicker(liveFeedAuthInterval)
	defer ticker.Stop()
	lastAuth := time.Now()
	stillAuthorized := func(force bool) bool {
		if !force && time.Since(lastAuth) < liveFeedAuthInterval {
			return true
		}
		if !h.feedSessionValid(c, user, token) {
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
		batch = feed.After(cursor)
		if batch.Oldest > 0 && cursor < batch.Oldest-1 {
			if err := write("gap", "", map[string]uint64{"dropped": batch.Oldest - 1 - cursor}); err != nil {
				return nil
			}
		}
		for _, event := range batch.Events {
			if !stillAuthorized(false) {
				return nil
			}
			if err := write("request", fmt.Sprintf("%s:%d", feed.Epoch(), event.ID), event); err != nil {
				return nil
			}
			cursor = event.ID
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
