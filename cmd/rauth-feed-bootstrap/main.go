// rauth-feed-bootstrap seeds the requested default before enabling the new
// runtime, avoiding a cold-start loop when the feed source also uses RAuth.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"rauth/internal/core"
	"time"
)

func main() {
	cfg := core.LoadConfig()
	if err := core.InitPostgres(cfg); err != nil {
		slog.Error("Default feed bootstrap database initialization failed", "error", err)
		os.Exit(1)
	}
	defer core.PG.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := core.EnsureDefaultIPFeed(ctx); err != nil {
		slog.Error("Default feed catalog initialization failed", "error", err)
		os.Exit(1)
	}
	if err := core.RefreshIPFeed(ctx, core.DefaultIPFeedID, core.FeedRefreshOptions{}); err != nil {
		slog.Error("Default feed download failed; do not activate public policy yet", "error", err)
		os.Exit(1)
	}
	feed, err := core.GetIPFeed(ctx, core.DefaultIPFeedID)
	if err != nil {
		slog.Error("Default feed read failed", "error", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"feed_id": feed.ID, "version": feed.Version, "entries": feed.EntryCount, "ready": feed.Ready()}); err != nil {
		slog.Error("Default feed bootstrap result could not be written")
		os.Exit(1)
	}
}
