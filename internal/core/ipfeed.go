package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const policyMutationLockID int64 = 0x726175746670

var ErrIPFeedNotFound = errors.New("IP feed not found")
var ErrIPFeedInUse = errors.New("remove this feed from its URL rules before disabling or deleting it")
var ErrIPFeedBusy = errors.New("feed refresh is already running")

type IPFeed struct {
	ID             string
	Name           string
	SourceURL      string `json:"-"`
	RefreshMinutes int
	Enabled        bool
	Version        int64
	EntryCount     int
	LastSuccess    int64
	LastAttempt    int64
	LastError      string
	Revision       int64
	Rules          []string
}

func (f IPFeed) DisplayURL() string {
	u, err := url.Parse(f.SourceURL)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
func (f IPFeed) Ready() bool          { return f.Enabled && f.Version > 0 }
func (f IPFeed) RefreshPending() bool { return f.Ready() && f.LastAttempt == 0 }
func (f IPFeed) Stale() bool {
	return f.LastSuccess > 0 && time.Now().Unix()-f.LastSuccess > int64(f.RefreshMinutes*120)
}
func policyMutation(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, PG, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", policyMutationLockID); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "UPDATE cluster_policy_source_state SET revision=revision+1 WHERE singleton")
		if err == nil && tag.RowsAffected() != 1 {
			return errors.New("policy source revision is unavailable")
		}
		return err
	})
}

const feedColumns = "id::text,name,source_url,refresh_minutes,enabled,active_version,entry_count,last_success,last_attempt,last_error,revision"

func readFeed(row pgx.Row) (IPFeed, error) {
	var f IPFeed
	err := row.Scan(&f.ID, &f.Name, &f.SourceURL, &f.RefreshMinutes, &f.Enabled, &f.Version, &f.EntryCount, &f.LastSuccess, &f.LastAttempt, &f.LastError, &f.Revision)
	if isNoRows(err) {
		return f, ErrIPFeedNotFound
	}
	return f, err
}
func GetIPFeed(ctx context.Context, id string) (IPFeed, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return IPFeed{}, ErrIPFeedNotFound
	}
	id = parsed.String()
	return readFeed(PG.QueryRow(ctx, "SELECT "+feedColumns+" FROM ip_feeds WHERE id=$1", id))
}
func ListIPFeeds(ctx context.Context) ([]IPFeed, error) {
	rows, err := PG.Query(ctx, "SELECT "+feedColumns+" FROM ip_feeds ORDER BY lower(name),id")
	if err != nil {
		return nil, err
	}
	var result []IPFeed
	for rows.Next() {
		f, err := readFeed(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	refs, err := PG.Query(ctx, "SELECT feed_id::text,rule FROM bypass_rule_feeds ORDER BY rule")
	if err != nil {
		return nil, err
	}
	defer refs.Close()
	for refs.Next() {
		var id, rule string
		if err := refs.Scan(&id, &rule); err != nil {
			return nil, err
		}
		for i := range result {
			if result[i].ID == id {
				result[i].Rules = append(result[i].Rules, rule)
				break
			}
		}
	}
	return result, refs.Err()
}
func validateFeedInput(name, source string, minutes int) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 || strings.ContainsAny(name, "\r\n\x00") {
		return "", "", errors.New("feed name must contain 1 to 120 characters")
	}
	u, err := validateFeedURL(source)
	if err != nil {
		return "", "", err
	}
	if minutes < 15 || minutes > 1440 {
		return "", "", errors.New("refresh interval must be 15 to 1440 minutes")
	}
	return name, u.String(), nil
}
func AddIPFeed(ctx context.Context, name, source string, minutes int, admin string) (IPFeed, error) {
	name, source, err := validateFeedInput(name, source, minutes)
	if err != nil {
		return IPFeed{}, err
	}
	f := IPFeed{ID: uuid.NewString(), Name: name, SourceURL: source, RefreshMinutes: minutes, Enabled: true, Revision: 1}
	err = policyMutation(ctx, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM ip_feeds").Scan(&count); err != nil {
			return err
		}
		if count >= MaxIPFeeds {
			return errors.New("maximum number of IP feeds reached")
		}
		_, err := tx.Exec(ctx, `INSERT INTO ip_feeds(id,name,source_url,refresh_minutes,created_by,created_at,updated_by,updated_at) VALUES($1,$2,$3,$4,$5,$6,$5,$6)`, f.ID, name, source, minutes, admin, time.Now().Unix())
		return err
	})
	return f, err
}
func UpdateIPFeed(ctx context.Context, id, name, source string, minutes int, enabled bool, admin string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return ErrIPFeedNotFound
	}
	id = parsed.String()
	return policyMutation(ctx, func(tx pgx.Tx) error {
		old, err := readFeed(tx.QueryRow(ctx, "SELECT "+feedColumns+" FROM ip_feeds WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if source == "" {
			source = old.SourceURL
		}
		if old.IsDefault() && (!enabled || source != DefaultIPFeedURL) {
			return errors.New("the built-in default feed must remain enabled at its configured source")
		}
		name, source, err = validateFeedInput(name, source, minutes)
		if err != nil {
			return err
		}
		if enabled && !old.Enabled {
			var total int
			if err := tx.QueryRow(ctx, "SELECT COALESCE(sum(entry_count),0) FROM ip_feeds WHERE enabled AND id<>$1", id).Scan(&total); err != nil {
				return err
			}
			if total+old.EntryCount > MaxWorkerFeedPrefixes {
				return errors.New("combined feed prefix limit exceeded")
			}
		}
		if !enabled {
			var used bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM bypass_rule_feeds WHERE feed_id=$1)", id).Scan(&used); err != nil {
				return err
			}
			if used {
				return ErrIPFeedInUse
			}
		}
		_, err = tx.Exec(ctx, `UPDATE ip_feeds SET name=$2,
        last_attempt=CASE WHEN source_url<>$3 THEN 0 ELSE last_attempt END,
        refresh_lease_until=CASE WHEN source_url<>$3 THEN 0 ELSE refresh_lease_until END,
        lease_token=CASE WHEN source_url<>$3 THEN NULL ELSE lease_token END,
        last_error=CASE WHEN source_url<>$3 THEN '' ELSE last_error END,
        source_url=$3,refresh_minutes=$4,enabled=$5,revision=revision+1,updated_by=$6,updated_at=$7 WHERE id=$1`, id, name, source, minutes, enabled, admin, time.Now().Unix())
		return err
	})
}
func DeleteIPFeed(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return ErrIPFeedNotFound
	}
	id = parsed.String()
	if id == DefaultIPFeedID {
		return errors.New("the built-in default feed cannot be deleted")
	}
	return policyMutation(ctx, func(tx pgx.Tx) error {
		var used bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM bypass_rule_feeds WHERE feed_id=$1)", id).Scan(&used); err != nil {
			return err
		}
		if used {
			return ErrIPFeedInUse
		}
		tag, err := tx.Exec(ctx, "DELETE FROM ip_feeds WHERE id=$1", id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrIPFeedNotFound
		}
		return err
	})
}
func syncRuleFeedReferences(ctx context.Context, tx pgx.Tx, rule string, ids []string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM bypass_rule_feeds WHERE rule=$1", rule); err != nil {
		return err
	}
	for _, id := range ids {
		var ready bool
		if err := tx.QueryRow(ctx, "SELECT enabled AND active_version>0 FROM ip_feeds WHERE id=$1 FOR SHARE", id).Scan(&ready); err != nil {
			if isNoRows(err) {
				return errors.New("selected feed does not exist")
			}
			return err
		}
		if !ready {
			return errors.New("selected feed must be enabled and successfully refreshed first")
		}
		if _, err := tx.Exec(ctx, "INSERT INTO bypass_rule_feeds(rule,feed_id) VALUES($1,$2)", rule, id); err != nil {
			return err
		}
	}
	return nil
}

type feedSnapshot struct {
	defaultConfigured bool
	indexes           map[string]*compiledIPFeed
	versions          map[string]int64
}

var activeFeeds atomic.Pointer[feedSnapshot]
var feedReloadMu sync.Mutex

func init() {
	activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}})
}
func ReloadIPFeeds(ctx context.Context) error {
	feedReloadMu.Lock()
	defer feedReloadMu.Unlock()
	feeds, err := ListIPFeeds(ctx)
	if err != nil {
		return err
	}
	current := activeFeeds.Load()
	defaultConfigured := current.defaultConfigured
	for _, feed := range feeds {
		if feed.IsDefault() {
			defaultConfigured = true
		}
	}
	same := current.defaultConfigured == defaultConfigured
	ready := 0
	for _, f := range feeds {
		if f.Ready() {
			ready++
			if current.versions[f.ID] != f.Version {
				same = false
			}
		}
	}
	if same && len(current.versions) == ready {
		return nil
	}
	next := &feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}, defaultConfigured: defaultConfigured}
	total := 0
	for _, f := range feeds {
		if !f.Ready() {
			continue
		}
		var payload []byte
		var checksum string
		if err := PG.QueryRow(ctx, "SELECT payload,checksum FROM ip_feed_versions WHERE feed_id=$1 AND version=$2", f.ID, f.Version).Scan(&payload, &checksum); err != nil {
			return err
		}
		hash := sha256.Sum256(payload)
		if hex.EncodeToString(hash[:]) != checksum {
			return errors.New("feed snapshot checksum failed")
		}
		index, _, err := parseFeed(payload, true)
		if err != nil {
			return err
		}
		total += index.count
		if total > MaxWorkerFeedPrefixes {
			return errors.New("combined feed prefix limit exceeded")
		}
		next.indexes[f.ID] = index
		next.versions[f.ID] = f.Version
	}
	activeFeeds.Store(next)
	return nil
}

// snapshot is initialized by package init in legacy mode, or embedded as a
// non-nil value in every compiled worker snapshot.
func matchSnapshotFeeds(snapshot *feedSnapshot, ids []string, address netip.Addr) PolicyDecision {
	for _, id := range ids {
		index, ok := snapshot.indexes[id]
		if !ok {
			return PolicyDecision{Allowed: false, Reason: "ip_feed_unavailable", FeedID: id}
		}
		if index.contains(address) {
			return PolicyDecision{Allowed: false, Reason: "ip_feed_blocked", FeedID: id}
		}
	}
	return PolicyDecision{Allowed: true}
}

type FeedRefreshOptions struct{ AcceptEmpty, AcceptLargeDrop bool }

func RefreshIPFeed(ctx context.Context, id string, options FeedRefreshOptions) error {
	return refreshIPFeed(ctx, id, options, newFeedClient())
}
func refreshIPFeed(ctx context.Context, id string, options FeedRefreshOptions, client *http.Client) (result error) {
	f, err := GetIPFeed(ctx, id)
	if err != nil {
		return err
	}
	if !f.Enabled {
		return errors.New("enable the feed before refreshing")
	}
	lease := uuid.NewString()
	now := time.Now().Unix()
	tag, err := PG.Exec(ctx, `UPDATE ip_feeds SET refresh_lease_until=$2,lease_token=$3,last_attempt=$4 WHERE id=$1 AND revision=$5 AND refresh_lease_until<$4`, id, now+60, lease, now, f.Revision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrIPFeedBusy
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		message := ""
		if result != nil {
			message = result.Error()
			if len(message) > 200 {
				message = "feed refresh failed"
			}
		}
		_, _ = PG.Exec(cleanup, `UPDATE ip_feeds SET refresh_lease_until=0,lease_token=NULL,last_error=$3 WHERE id=$1 AND lease_token=$2`, id, lease, message)
	}()
	body, err := fetchIPFeed(ctx, client, f.SourceURL)
	if err != nil {
		return err
	}
	index, normalized, err := parseFeed(body, options.AcceptEmpty || (f.Version > 0 && f.EntryCount == 0))
	if err != nil {
		return err
	}
	if f.EntryCount > 0 && index.count*2 < f.EntryCount && !options.AcceptLargeDrop && (index.count != 0 || !options.AcceptEmpty) {
		return errors.New("feed lost over half its entries; explicit acceptance required")
	}
	checksum := sha256.Sum256(normalized)
	digest := hex.EncodeToString(checksum[:])
	err = policyMutation(ctx, func(tx pgx.Tx) error {
		current, err := readFeed(tx.QueryRow(ctx, "SELECT "+feedColumns+" FROM ip_feeds WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if current.Revision != f.Revision || !current.Enabled {
			return errors.New("feed was edited during refresh; retry")
		}
		var token string
		if err := tx.QueryRow(ctx, "SELECT COALESCE(lease_token::text,'') FROM ip_feeds WHERE id=$1", id).Scan(&token); err != nil {
			return err
		}
		if token != lease {
			return errors.New("feed refresh lease expired")
		}
		var total int
		if err := tx.QueryRow(ctx, "SELECT COALESCE(sum(entry_count),0) FROM ip_feeds WHERE enabled AND id<>$1", id).Scan(&total); err != nil {
			return err
		}
		if total+index.count > MaxWorkerFeedPrefixes {
			return errors.New("combined feed prefix limit exceeded")
		}
		version := current.Version
		previous := ""
		if version > 0 {
			if err := tx.QueryRow(ctx, "SELECT checksum FROM ip_feed_versions WHERE feed_id=$1 AND version=$2", id, version).Scan(&previous); err != nil {
				return err
			}
		}
		if digest != previous {
			version++
			if _, err := tx.Exec(ctx, "INSERT INTO ip_feed_versions(feed_id,version,checksum,payload,created_at) VALUES($1,$2,$3,$4,$5)", id, version, digest, normalized, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE ip_feeds SET active_version=$2,entry_count=$3,last_success=$4,last_error='' WHERE id=$1`, id, version, index.count, now); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "DELETE FROM ip_feed_versions WHERE feed_id=$1 AND version<$2", id, version-2)
		return err
	})
	if err != nil {
		return err
	}
	return ReloadIPFeeds(ctx)
}
func normalizeFeedIDs(ids []string) ([]string, error) {
	if len(ids) > MaxIPFeeds {
		return nil, errors.New("too many attached feeds")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return nil, errors.New("invalid feed ID")
		}
		seen[parsed.String()] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// StartIPFeedService returns a joined stop function: callers can safely close
// test/storage resources after stopping the scheduler and its bounded workers.
func StartIPFeedService(parent context.Context, fetch bool) func() {
	ctx, cancel := context.WithCancel(parent)
	if err := ReloadIPFeeds(ctx); err != nil {
		slog.Error("IP feed snapshot load failed", "error", err)
	}
	done := make(chan struct{})
	sem := make(chan struct{}, 2)
	var jobs sync.WaitGroup
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				jobs.Wait()
				return
			case <-ticker.C:
			}
			if err := ReloadIPFeeds(ctx); err != nil {
				slog.Error("Keeping last good IP feed snapshot", "error", err)
			}
			if !fetch {
				continue
			}
			feeds, err := ListIPFeeds(ctx)
			if err != nil {
				continue
			}
			for _, f := range feeds {
				if !ipFeedRefreshDue(f, time.Now().Unix()) {
					continue
				}
				select {
				case sem <- struct{}{}:
				default:
					continue
				}
				jobs.Add(1)
				go func(id string) {
					defer jobs.Done()
					defer func() { <-sem }()
					if err := RefreshIPFeed(ctx, id, FeedRefreshOptions{}); err != nil && !errors.Is(err, ErrIPFeedBusy) && ctx.Err() == nil {
						slog.Warn("IP feed refresh failed", "feed_id", id, "error", err)
					}
				}(f.ID)
			}
		}
	}()
	return func() { cancel(); <-done }
}

// IPFeedPolicyReady is passive and does not couple public policy checks to
// collector/network availability. Last-good snapshots remain ready on errors.
func IPFeedPolicyReady() bool {
	snapshot := activeFeeds.Load()
	return !defaultFeedRequired() || snapshot.indexes[DefaultIPFeedID] != nil
}

func ipFeedRefreshDue(feed IPFeed, now int64) bool {
	if !feed.Enabled {
		return false
	}
	seconds := int64(feed.RefreshMinutes * 60)
	if feed.Version == 0 {
		seconds = 60
	}
	return now-feed.LastAttempt >= seconds
}
