package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// redisImportMarker records in app_meta that the one-time import ran.
const redisImportMarker = "redis_import"

// ImportFromRedis copies the durable data that versions before the Postgres
// store kept in Redis (DB 0: accounts, passkeys, recovery codes, auth
// generations, bypass rules; DB 3: audit log) into Postgres. It runs once, in
// a single transaction, and only into an empty users table. Redis is left
// untouched so a rollback to the previous image keeps working.
func ImportFromRedis(cfg *Config) error {
	var done bool
	if err := PG.QueryRow(Ctx, "SELECT EXISTS (SELECT 1 FROM app_meta WHERE key = $1)", redisImportMarker).Scan(&done); err != nil {
		return err
	}
	if done {
		return nil
	}

	opts := redisOptions(cfg)
	userDB := redis.NewClient(copyOptions(opts, redisLegacyUserDB))
	defer func() { _ = userDB.Close() }()
	auditDB := redis.NewClient(copyOptions(opts, redisLegacyAuditDB))
	defer func() { _ = auditDB.Close() }()
	return importFromRedis(Ctx, userDB, auditDB)
}

// importStats counts what an import copied, for the log.
type importStats struct {
	Users, Passkeys, RecoveryCodes, AuthGenerations, BypassRules, AuditEntries int
}

func importFromRedis(ctx context.Context, userDB, auditDB *redis.Client) error {
	var stats importStats
	err := pgx.BeginFunc(ctx, PG, func(tx pgx.Tx) error {
		// Serialize concurrent starts; the loser sees the marker afterwards.
		if _, err := tx.Exec(ctx, "LOCK TABLE app_meta IN EXCLUSIVE MODE"); err != nil {
			return err
		}
		var done, hasUsers bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_meta WHERE key = $1),
			EXISTS (SELECT 1 FROM users)`, redisImportMarker).Scan(&done, &hasUsers); err != nil {
			return err
		}
		if done {
			return nil
		}
		if hasUsers {
			slog.Warn("Postgres already holds users; skipping Redis import")
		} else {
			var err error
			if stats, err = copyRedisData(ctx, tx, userDB, auditDB); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, "INSERT INTO app_meta (key, value) VALUES ($1, $2)", redisImportMarker,
			fmt.Sprintf("users=%d passkeys=%d recovery_codes=%d auth_generations=%d bypass_rules=%d audit_entries=%d",
				stats.Users, stats.Passkeys, stats.RecoveryCodes, stats.AuthGenerations, stats.BypassRules, stats.AuditEntries))
		return err
	})
	if err != nil {
		return fmt.Errorf("redis import failed: %w", err)
	}
	if stats != (importStats{}) {
		slog.Info("Imported data from Redis into Postgres",
			"users", stats.Users, "passkeys", stats.Passkeys, "recovery_codes", stats.RecoveryCodes,
			"auth_generations", stats.AuthGenerations, "bypass_rules", stats.BypassRules, "audit_entries", stats.AuditEntries)
	}
	return nil
}

func scanKeys(ctx context.Context, client *redis.Client, pattern string) ([]string, error) {
	var keys []string
	iter := client.Scan(ctx, 0, pattern, 500).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	return keys, iter.Err()
}

func copyRedisData(ctx context.Context, tx pgx.Tx, userDB, auditDB *redis.Client) (importStats, error) {
	var stats importStats

	// Accounts: "user:<name>" hashes. Usernames cannot contain ':', which
	// separates them from the per-user satellite keys. Hashes without a
	// username field are stubs left by stale writes, not accounts.
	keys, err := scanKeys(ctx, userDB, "user:*")
	if err != nil {
		return stats, err
	}
	var usernames []string
	for _, key := range keys {
		name := strings.TrimPrefix(key, "user:")
		if strings.Contains(name, ":") {
			continue
		}
		if t, err := userDB.Type(ctx, key).Result(); err != nil || t != "hash" {
			continue
		}
		h, err := userDB.HGetAll(ctx, key).Result()
		if err != nil {
			return stats, err
		}
		if h["username"] == "" {
			continue
		}
		var uid any
		if parsed, err := uuid.Parse(h["uid"]); err == nil {
			uid = parsed
		}
		createdAt, _ := strconv.ParseInt(h["created_at"], 10, 64)
		groups := h["groups"]
		if groups == "" {
			groups = "default"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (username, password, email, groups, is_admin, totp_secret, uid, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			name, h["password"], h["email"], groups, h["is_admin"] == "1", h["2fa_secret"], uid, createdAt); err != nil {
			return stats, fmt.Errorf("user %s: %w", name, err)
		}
		usernames = append(usernames, name)
		stats.Users++
	}

	for _, name := range usernames {
		// Passkeys: the v2 hash (field = hex credential ID), else the legacy list.
		creds := map[string]string{}
		hash, err := userDB.HGetAll(ctx, "user:"+name+":webauthn_creds_v2").Result()
		if err != nil {
			return stats, err
		}
		for id, data := range hash {
			creds[id] = data
		}
		if len(creds) == 0 {
			list, err := userDB.LRange(ctx, "user:"+name+":webauthn_creds", 0, -1).Result()
			if err != nil {
				return stats, err
			}
			for _, data := range list {
				var c StoredCredential
				if json.Unmarshal([]byte(data), &c) == nil && len(c.ID) > 0 {
					creds[fmt.Sprintf("%x", c.ID)] = data
				}
			}
		}
		for id, data := range creds {
			var c StoredCredential
			if err := json.Unmarshal([]byte(data), &c); err != nil || len(c.ID) == 0 {
				slog.Warn("Skipping unreadable passkey during import", "user", name, "credential", id)
				continue
			}
			if _, err := tx.Exec(ctx, "INSERT INTO webauthn_credentials (username, cred_id, data, created_at) VALUES ($1, $2, $3, $4)",
				name, id, []byte(data), c.CreatedAt); err != nil {
				return stats, fmt.Errorf("passkey of %s: %w", name, err)
			}
			stats.Passkeys++
		}

		codes, err := userDB.SMembers(ctx, "user:"+name+":recovery_codes").Result()
		if err != nil {
			return stats, err
		}
		if len(codes) > 0 {
			if _, err := tx.Exec(ctx, "INSERT INTO recovery_codes (username, code_hash) SELECT $1, unnest($2::text[])", name, codes); err != nil {
				return stats, fmt.Errorf("recovery codes of %s: %w", name, err)
			}
			stats.RecoveryCodes += len(codes)
		}
	}

	// Auth generations, including those of deleted accounts.
	genKeys, err := scanKeys(ctx, userDB, "authgen:*")
	if err != nil {
		return stats, err
	}
	for _, key := range genKeys {
		v, err := userDB.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		gen, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			continue
		}
		if _, err := tx.Exec(ctx, "INSERT INTO auth_generations (username, gen) VALUES ($1, $2)", strings.TrimPrefix(key, "authgen:"), gen); err != nil {
			return stats, err
		}
		stats.AuthGenerations++
	}

	// Bypass rules: field = rule, value = JSON metadata. Unreadable metadata
	// cannot go into a jsonb column; it is imported as a deny rule (fail closed).
	rules, err := userDB.HGetAll(ctx, "auth_bypass_rules").Result()
	if err != nil {
		return stats, err
	}
	for rule, meta := range rules {
		if !json.Valid([]byte(meta)) {
			slog.Warn("Bypass rule metadata unreadable; importing it as a deny rule", "rule", rule)
			meta = `{"action":"deny"}`
		}
		if _, err := tx.Exec(ctx, "INSERT INTO bypass_rules (rule, meta) VALUES ($1, $2)", rule, []byte(meta)); err != nil {
			return stats, err
		}
		stats.BypassRules++
	}

	// Audit log: the global list plus the per-user lists, which can reach
	// further back. Entries appear in both, so identical payloads are merged.
	raw := map[string]struct{}{}
	global, err := auditDB.LRange(ctx, "audit_logs", 0, -1).Result()
	if err != nil {
		return stats, err
	}
	for _, e := range global {
		raw[e] = struct{}{}
	}
	userLogKeys, err := scanKeys(ctx, auditDB, "user_audit_logs:*")
	if err != nil {
		return stats, err
	}
	for _, key := range userLogKeys {
		entries, err := auditDB.LRange(ctx, key, 0, -1).Result()
		if err != nil {
			return stats, err
		}
		for _, e := range entries {
			raw[e] = struct{}{}
		}
	}
	var entries []AuditLog
	for e := range raw {
		var l AuditLog
		if json.Unmarshal([]byte(e), &l) == nil && l.Action != "" {
			entries = append(entries, l)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Timestamp < entries[j].Timestamp })
	for _, l := range entries {
		details, _ := json.Marshal(l.Details)
		if l.Details == nil {
			details = []byte("{}")
		}
		if _, err := tx.Exec(ctx, "INSERT INTO audit_logs (ts, action, username, ip, details) VALUES ($1, $2, $3, $4, $5)",
			l.Timestamp, l.Action, l.Username, l.IP, details); err != nil {
			return stats, err
		}
		stats.AuditEntries++
	}

	return stats, nil
}
