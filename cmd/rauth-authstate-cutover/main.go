// Command rauth-authstate-cutover is an offline fleet-wide authority change.
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"time"

	"rauth/internal/core"
)

func main() {
	expire := flag.Bool("expire-legacy-state", false, "Commit the offline SQL cutover; every legacy session, pending login and invitation will expire")
	flag.Parse()
	if !*expire || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	cfg := core.LoadConfig()
	if cfg.AuthStateMode != "postgres" {
		slog.Error("Set AUTH_STATE_MODE=postgres for this offline operation")
		os.Exit(2)
	}
	if err := core.InitPostgres(cfg); err != nil {
		slog.Error("Cutover database initialization failed", "error", err)
		os.Exit(1)
	}
	defer core.PG.Close()
	deadline, err := core.CommitSQLAuthenticationCutover(core.Ctx, cfg)
	if err != nil {
		slog.Error("SQL authority cutover failed", "error", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"authority": "postgres-v1", "legacy_state_expired": true, "ready_after": deadline.UTC().Format(time.RFC3339Nano)}); err != nil {
		slog.Error("Writing cutover result failed", "error", err)
		os.Exit(1)
	}
}
