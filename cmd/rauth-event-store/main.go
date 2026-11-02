// Command rauth-event-store performs offline event schema migration/provisioning.
// Runtime nodes never invoke this command or acquire operator credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"os"
	"rauth/internal/clusterconfig"
	"rauth/internal/eventstore"
	"time"
)

func main() {
	node := flag.String("node-config", "", "Existing guarded control node JSON")
	operator := flag.String("operator-url-file", "", "Existing private operator URL file under the same guarded host root")
	role := flag.String("runtime-role", "", "Existing non-owner runtime database role")
	flag.Parse()
	if flag.NArg() != 0 || *node == "" || *operator == "" || *role == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*node, *operator, *role); err != nil {
		slog.Error("Event database migration/provisioning failed", "class", failureClass(err))
		os.Exit(1)
	}
}
func run(node, operator, role string) error {
	loaded, err := clusterconfig.Load(node)
	if err != nil {
		return err
	}
	dsn, err := loaded.EventOperatorURL(operator)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return eventstore.ErrInvalid
	}
	config.MaxConns = 3
	config.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return eventstore.ErrUnavailable
	}
	defer pool.Close()
	spec := loaded.Config()
	o := eventstore.Options{ClusterID: spec.ClusterID, MaxBytes: spec.Events.CentralMaxBytes, MaxAge: time.Duration(spec.Events.CentralMaxAgeSeconds) * time.Second}
	if o.MaxBytes == 0 {
		o.MaxBytes = eventstore.CentralBytes
	}
	if o.MaxAge == 0 {
		o.MaxAge = 7 * 24 * time.Hour
	}
	if err = eventstore.Migrate(ctx, pool); err != nil {
		return err
	}
	if err = eventstore.Provision(ctx, pool, o, role); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 2, "provisioned": true})
}

func failureClass(err error) string {
	switch {
	case errors.Is(err, clusterconfig.ErrMount):
		return "host_mount"
	case errors.Is(err, clusterconfig.ErrPrivateFile):
		return "private_file"
	case errors.Is(err, clusterconfig.ErrInvalid), errors.Is(err, eventstore.ErrInvalid):
		return "configuration"
	case errors.Is(err, eventstore.ErrUnavailable):
		return "database_unavailable"
	default:
		return "operation_failed"
	}
}
