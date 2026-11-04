package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	dto "github.com/prometheus/client_model/go"
	"net/http"
	"rauth/internal/core"
	"rauth/internal/eventstore"
	"strconv"
	"time"
)

type StatsSource interface {
	Statistics(context.Context, eventstore.StatsQuery) (eventstore.StatsSnapshot, error)
	Decisions(context.Context, eventstore.StatsQuery) ([]core.RequestEvent, error)
	Diagnostics(context.Context, string) (eventstore.Diagnostics, error)
}

func statsQuery(c echo.Context) (eventstore.StatsQuery, error) {
	q := eventstore.StatsQuery{Range: c.QueryParam("range"), Node: c.QueryParam("node"), Country: c.QueryParam("country"), Action: c.QueryParam("action"), Domain: c.QueryParam("domain"), Source: c.QueryParam("source"), URL: c.QueryParam("url"), Reason: c.QueryParam("reason")}
	if q.Range == "" {
		q.Range = "1h"
	}
	if raw := c.QueryParam("before"); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return q, eventstore.ErrInvalid
		}
		q.Before = n
	}
	_, _, err := q.Window(time.Now())
	return q, err
}
func (h *AdminHandler) StatsPage(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Render(http.StatusOK, "stats.html", map[string]any{"username": c.Get("username"), "root_user": h.Cfg.InitialUser, "csrf": c.Get("csrf"), "stats_page": true, "cluster_enabled": h.ReadPolicyStatus != nil, "users": []any{}, "sessions": []any{}, "bypass_rules": []any{}, "ip_feeds": []any{}})
}
func (h *AdminHandler) statsSource() (StatsSource, bool) {
	if source, ok := h.RequestEvents.(StatsSource); ok {
		return source, true
	}
	return h.LocalStats, h.LocalStats != nil
}
func (h *AdminHandler) statistics(c echo.Context, q eventstore.StatsQuery) (eventstore.StatsSnapshot, error) {
	source, ok := h.statsSource()
	if !ok {
		return eventstore.StatsSnapshot{}, eventstore.ErrUnavailable
	}
	return source.Statistics(c.Request().Context(), q)
}
func statsError(err error) error {
	if errors.Is(err, eventstore.ErrInvalid) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid Stats filter")
	}
	return echo.NewHTTPError(http.StatusServiceUnavailable, "Statistics unavailable; authentication remains independent")
}
func (h *AdminHandler) StatsData(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	q, err := statsQuery(c)
	if err != nil {
		return statsError(err)
	}
	data, err := h.statistics(c, q)
	if err != nil {
		return statsError(err)
	}
	return c.JSON(http.StatusOK, data)
}
func (h *AdminHandler) StatsHistory(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	q, err := statsQuery(c)
	if err != nil {
		return statsError(err)
	}
	source, ok := h.statsSource()
	if !ok {
		return statsError(eventstore.ErrUnavailable)
	}
	events, err := source.Decisions(c.Request().Context(), q)
	if err != nil {
		return statsError(err)
	}
	var next uint64
	if len(events) == 100 {
		next = events[len(events)-1].ID
	}
	return c.JSON(http.StatusOK, map[string]any{"events": events, "before": next})
}
func (h *AdminHandler) StatsDiagnostics(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	source, ok := h.statsSource()
	if !ok {
		return statsError(eventstore.ErrUnavailable)
	}
	data, err := source.Diagnostics(c.Request().Context(), c.QueryParam("node"))
	if err != nil {
		return statsError(err)
	}
	if c.QueryParam("download") == "1" {
		c.Response().Header().Set("Content-Disposition", `attachment; filename="rauth-node-metrics.json"`)
	}
	return c.JSON(http.StatusOK, data)
}

// Shared gauges are read once on the control node. They must not be added across
// worker snapshots, since each node sees the same authentication session store.
func (h *AdminHandler) StatsOperations(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	metric := &dto.Metric{}
	var active *float64
	if core.ActiveSessionsGauge.Write(metric) == nil && metric.Gauge != nil {
		v := metric.GetGauge().GetValue()
		active = &v
	}
	out := map[string]any{"active_sessions": active, "session_scope": "authoritative control observation", "checked_at": time.Now().UTC(), "ha_observation": "not configured"}
	if h.ReadHAStatus != nil {
		out["ha_observation"] = h.ReadHAStatus()
	}
	feedViews := []map[string]any{}
	ctxFeeds, cancelFeeds := context.WithTimeout(c.Request().Context(), time.Second)
	feeds, feedErr := core.ListIPFeeds(ctxFeeds)
	cancelFeeds()
	if feedErr == nil {
		for _, feed := range feeds {
			feedViews = append(feedViews, map[string]any{"id": feed.ID, "name": feed.Name, "enabled": feed.Enabled, "ready": feed.Ready(), "stale": feed.Stale(), "version": feed.Version, "entries": feed.EntryCount, "last_success": feed.LastSuccess, "refresh_failed": feed.LastError != ""})
		}
		out["feeds"] = feedViews
	} else {
		out["feeds_unavailable"] = true
	}
	if h.ReadPolicyStatus != nil {
		ctx, cancel := context.WithTimeout(c.Request().Context(), time.Second)
		defer cancel()
		status, err := h.ReadPolicyStatus(ctx)
		if err == nil {
			out["policy"] = status
		} else {
			out["policy_unavailable"] = true
		}
	}
	return c.JSON(http.StatusOK, out)
}
func (h *AdminHandler) StatsStream(c echo.Context) error {
	user, _ := c.Get("username").(string)
	token, _ := c.Get("token").(string)
	if user == "" || token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}
	if valid, err := h.feedSessionValid(c, user, token); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Authorization temporarily unavailable")
	} else if !valid {
		return echo.NewHTTPError(http.StatusForbidden)
	}
	q, err := statsQuery(c)
	if err != nil {
		return statsError(err)
	}
	if _, ok := c.Response().Writer.(http.Flusher); !ok {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	if !acquireFeedStream(user) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many admin streams")
	}
	defer releaseFeedStream(user)
	first, err := h.statistics(c, q)
	if err != nil {
		return statsError(err)
	}
	c.Response().Header().Set("Content-Type", "text/event-stream")
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("X-Accel-Buffering", "no")
	c.Response().WriteHeader(http.StatusOK)
	controller := http.NewResponseController(c.Response().Writer)
	write := func(kind string, data any) error {
		if err := controller.SetWriteDeadline(time.Now().Add(liveFeedWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		raw, err := json.Marshal(data)
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(c.Response(), "event: %s\ndata: %s\n\n", kind, raw); err != nil {
			return err
		}
		return controller.Flush()
	}
	if write("stats", first) != nil {
		return nil
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastAuth := time.Now()
	for {
		select {
		case <-c.Request().Context().Done():
			return nil
		case <-tick.C:
			if time.Since(lastAuth) >= liveFeedAuthInterval {
				valid, authErr := h.feedSessionValid(c, user, token)
				if authErr != nil {
					// Retry after a transport/store failure.
					return nil
				}
				if !valid {
					_ = write("session-ended", map[string]string{"message": "Administrator access ended"})
					return nil
				}
				lastAuth = time.Now()
			}
			data, err := h.statistics(c, q)
			if err != nil {
				if write("unavailable", map[string]string{"message": "Statistics unavailable; last snapshot is stale"}) != nil {
					return nil
				}
				continue
			}
			if write("stats", data) != nil {
				return nil
			}
		}
	}
}
