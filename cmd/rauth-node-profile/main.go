// rauth-node-profile derives non-secret desired enrollment without database IO.
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"rauth/internal/core"
)

func main() {
	node := flag.String("node-id", "", "Canonical enrolled node UUID")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	options, err := core.WorkerPolicyOptionsForConfig(*node, core.LoadConfig())
	if err != nil {
		slog.Error("Cannot derive a valid node security profile", "error", err)
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"node_id": options.NodeID, "security_fingerprint": options.SecurityFingerprint, "require_geoip": options.RequireGeoIP}) != nil {
		os.Exit(1)
	}
}
