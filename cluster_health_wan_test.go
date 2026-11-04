package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"rauth/internal/clusterpool"
	"rauth/internal/clusterregistry"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"rauth/internal/testfile"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type healthWANConn struct {
	net.Conn
	enabled *atomic.Bool
}

func (c *healthWANConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(400 * time.Millisecond)
	}
	return c.Conn.Write(p)
}
func healthWANPool(t *testing.T, base *pgxpool.Config, maximum int32, critical bool, enabled *atomic.Bool) *pgxpool.Pool {
	t.Helper()
	cfg := base.Copy()
	require.NoError(t, clusterpool.Configure(cfg, maximum, critical))
	u, err := url.Parse(cfg.ConnConfig.ConnString())
	require.NoError(t, err)
	q := u.Query()
	q.Set("target_session_attrs", "read-write")
	u.RawQuery = q.Encode()
	selected, err := pgxpool.ParseConfig(u.String())
	require.NoError(t, err)
	cfg.ConnConfig.ValidateConnect = selected.ConnConfig.ValidateConnect
	dial := cfg.ConnConfig.DialFunc
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &healthWANConn{c, enabled}, nil
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}
func TestClusterHealthAuthorityWAN400(t *testing.T) {
	if os.Getenv("RAUTH_HEALTH_WAN_CHILD") != "1" {
		if os.Getenv(pgtest.EnvURL) == "" {
			if os.Getenv("CI") != "" {
				t.Fatal("test database required")
			}
			t.Skip("test database required")
		}
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestClusterHealthAuthorityWAN400$", "-test.v", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "RAUTH_HEALTH_WAN_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		require.NoError(t, err)
		return
	}
	// SQL authority globals stay in this subprocess and a distinct disposable
	// schema; parent root tests cannot inherit an enabled authority or lose tables.
	os.Args[0] = "health-wan-" + uuid.NewString()
	write := pgtest.Open(t, core.Migrate)
	secret := strings.Repeat("synthetic-health-key-", 3)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("rauth-cluster-cookie-key-v1"))
	marker := map[string]any{"mode": "postgres-v1", "server_key_check": hex.EncodeToString(mac.Sum(nil)), "cutover_at": time.Now().Add(-10 * time.Minute), "ready_after": time.Now().Add(-8 * time.Minute), "legacy_expired": true}
	raw, err := json.Marshal(marker)
	require.NoError(t, err)
	_, err = write.Exec(t.Context(), "INSERT INTO app_meta(key,value)VALUES('redis_import','synthetic'),('auth_state_authority',$1)", string(raw))
	require.NoError(t, err)
	keys, err := json.Marshal(map[string]any{"index_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", 32))), "active_key_id": "v1", "encryption_keys": map[string]string{"v1": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))}})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "keys.json")
	testfile.WritePrivate(t, path, keys)
	core.PG = write
	require.NoError(t, core.InitAuthenticationState(&core.Config{ServerSecret: secret, AuthStateMode: "postgres", AuthStateKeyFile: path, TokenValidityMinutes: 30, AuthStateAbsoluteMinutes: 60}))
	enabled := &atomic.Bool{}
	defer enabled.Store(false)
	auth := healthWANPool(t, write.Config(), 4, false, enabled)
	require.NoError(t, auth.Ping(t.Context()))
	core.PG = auth
	registry := healthWANPool(t, write.Config(), 2, true, enabled)
	require.NoError(t, clusterpool.Warm(t.Context(), registry))
	cluster := uuid.NewString()
	entry := clusterregistry.Entry{NodeID: uuid.NewString(), Role: "worker", ServiceIP: netip.MustParseAddr("100.72.1.2"), Pins: [][32]byte{sha256.Sum256([]byte("synthetic-peer"))}, Scopes: []clustertransport.Scope{clustertransport.PolicyRead}, Enabled: true, ExpiresAt: time.Now().Add(time.Hour)}
	registrar, err := clusterregistry.NewRegistrar(write, cluster)
	require.NoError(t, err)
	_, err = registrar.Put(t.Context(), 0, entry)
	require.NoError(t, err)
	reader, err := clusterregistry.NewReader(registry, cluster)
	require.NoError(t, err)
	peer := clustertransport.Peer{ClusterID: cluster, NodeID: entry.NodeID, SPKI: entry.Pins[0], ServiceIP: entry.ServiceIP, ExpiresAt: entry.ExpiresAt}
	health := newClusterHealth(core.CheckAuthenticationAuthority, func(ctx context.Context) error { return reader.Authorize(ctx, peer, clustertransport.PolicyRead) })
	enabled.Store(true)
	time.Sleep(1200 * time.Millisecond)
	started := time.Now()
	health.refresh(t.Context())
	a, e := health.status()
	t.Logf("full400ms_health_after_idle elapsed=%s auth=%t enrolled=%t", time.Since(started), a, e)
	require.True(t, a)
	require.True(t, e)
	entry.Enabled = false
	_, err = registrar.Put(t.Context(), 1, entry)
	require.NoError(t, err)
	health.refresh(t.Context())
	a, e = health.status()
	require.True(t, a)
	require.False(t, e)
}
