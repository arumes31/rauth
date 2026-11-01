package handlers

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"rauth/internal/core"
	"strconv"
)

func feedFormError(err error) error { return echo.NewHTTPError(http.StatusBadRequest, err.Error()) }
func (h *AdminHandler) AddIPFeed(c echo.Context) error {
	if err := requireBypassUnlock(c); err != nil {
		return err
	}
	minutes, err := strconv.Atoi(c.FormValue("refresh_minutes"))
	if err != nil {
		return echo.NewHTTPError(400, "Invalid refresh interval")
	}
	f, err := core.AddIPFeed(c.Request().Context(), c.FormValue("name"), c.FormValue("source_url"), minutes, c.Get("username").(string))
	if err != nil {
		return feedFormError(err)
	}
	core.LogAudit("ADMIN_IP_FEED_ADD", c.Get("username").(string), c.RealIP(), map[string]interface{}{"feed_id": f.ID, "name": f.Name})
	return c.Redirect(303, "/rauthmgmt?success=feed_added#ip-feeds")
}
func (h *AdminHandler) UpdateIPFeed(c echo.Context) error {
	if err := requireBypassUnlock(c); err != nil {
		return err
	}
	minutes, err := strconv.Atoi(c.FormValue("refresh_minutes"))
	if err != nil {
		return echo.NewHTTPError(400, "Invalid refresh interval")
	}
	enabled := c.FormValue("enabled")
	if enabled != "" && enabled != "on" {
		return echo.NewHTTPError(400, "Invalid enabled value")
	}
	id := c.FormValue("feed_id")
	err = core.UpdateIPFeed(c.Request().Context(), id, c.FormValue("name"), c.FormValue("source_url"), minutes, enabled == "on", c.Get("username").(string))
	if err != nil {
		return feedFormError(err)
	}
	core.LogAudit("ADMIN_IP_FEED_UPDATE", c.Get("username").(string), c.RealIP(), map[string]interface{}{"feed_id": id, "enabled": enabled == "on"})
	return c.Redirect(303, "/rauthmgmt?success=feed_updated#ip-feeds")
}
func (h *AdminHandler) DeleteIPFeed(c echo.Context) error {
	if err := requireBypassUnlock(c); err != nil {
		return err
	}
	id := c.FormValue("feed_id")
	if err := core.DeleteIPFeed(c.Request().Context(), id); err != nil {
		return feedFormError(err)
	}
	core.LogAudit("ADMIN_IP_FEED_DELETE", c.Get("username").(string), c.RealIP(), map[string]interface{}{"feed_id": id})
	return c.Redirect(303, "/rauthmgmt?success=feed_deleted#ip-feeds")
}
func (h *AdminHandler) RefreshIPFeed(c echo.Context) error {
	if err := requireBypassUnlock(c); err != nil {
		return err
	}
	id := c.FormValue("feed_id")
	empty, drop := c.FormValue("accept_empty"), c.FormValue("accept_large_drop")
	if (empty != "" && empty != "on") || (drop != "" && drop != "on") {
		return echo.NewHTTPError(400, "Invalid acceptance option")
	}
	err := core.RefreshIPFeed(c.Request().Context(), id, core.FeedRefreshOptions{AcceptEmpty: empty == "on", AcceptLargeDrop: drop == "on"})
	if err != nil {
		return feedFormError(err)
	}
	core.LogAudit("ADMIN_IP_FEED_REFRESH", c.Get("username").(string), c.RealIP(), map[string]interface{}{"feed_id": id, "accept_empty": empty == "on", "accept_large_drop": drop == "on"})
	return c.Redirect(303, "/rauthmgmt?success=feed_refreshed#ip-feeds")
}

func (h *AdminHandler) PreviewPolicy(c echo.Context) error {
	result, err := core.PreviewURLPolicy(c.FormValue("url"), c.FormValue("client_ip"))
	if err != nil {
		return feedFormError(err)
	}
	return c.JSON(http.StatusOK, result)
}
