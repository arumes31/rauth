package core

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const DefaultIPFeedURL = "https://blocklist.eworx.at/api/v1/raw"

var DefaultIPFeedID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(DefaultIPFeedURL)).String()

func (f IPFeed) IsDefault() bool { return f.ID == DefaultIPFeedID }

// EnsureDefaultIPFeed installs the user's managed default and backfills public
// rules once. An explicit administrator choice is preserved on later starts.
// Run the bootstrap command while the prior feed-serving route is available.
func EnsureDefaultIPFeed(ctx context.Context) error {
	changed := 0
	err := policyMutation(ctx, func(tx pgx.Tx) error {
		var exists bool
		var count int
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ip_feeds WHERE id=$1), (SELECT count(*) FROM ip_feeds)", DefaultIPFeedID).Scan(&exists, &count); err != nil {
			return err
		}
		if !exists && count >= MaxIPFeeds {
			return errors.New("remove a custom feed to make room for the built-in default feed")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO ip_feeds(id,name,source_url,refresh_minutes,created_by,created_at,updated_by,updated_at) VALUES($1,'Eworx default blocklist',$2,60,'system',extract(epoch from now())::bigint,'system',extract(epoch from now())::bigint) ON CONFLICT(id) DO NOTHING`, DefaultIPFeedID, DefaultIPFeedURL)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			changed++
		}
		rows, err := tx.Query(ctx, "SELECT rule,meta FROM bypass_rules FOR UPDATE")
		if err != nil {
			return err
		}
		type record struct {
			rule string
			meta []byte
		}
		var records []record
		for rows.Next() {
			var r record
			if err := rows.Scan(&r.rule, &r.meta); err != nil {
				rows.Close()
				return err
			}
			records = append(records, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, record := range records {
			var rule BypassRule
			if err := json.Unmarshal(record.meta, &rule); err != nil {
				return errors.New("invalid stored rule during default-feed initialization")
			}
			action, err := normalizeAction(rule.Action)
			if err != nil || action == BypassDeny || rule.DefaultFeedConfigured {
				continue
			}
			rule.BlockedFeedIDs = appendFeedID(rule.BlockedFeedIDs, DefaultIPFeedID)
			rule.DefaultFeedConfigured = true
			rule.UpdatedBy = "system"
			rule.UpdatedAt = time.Now().Unix()
			body, err := json.Marshal(rule)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "UPDATE bypass_rules SET meta=$2 WHERE rule=$1", record.rule, body); err != nil {
				return err
			}
			// The initial default may still be pending. Authorization fails closed until
			// its validated snapshot exists; deployment must bootstrap before cutover.
			if _, err := tx.Exec(ctx, "INSERT INTO bypass_rule_feeds(rule,feed_id) VALUES($1,$2) ON CONFLICT DO NOTHING", record.rule, DefaultIPFeedID); err != nil {
				return err
			}
			changed++
		}
		return nil
	})
	if err == nil && changed > 0 {
		LogAudit("IP_FEED_DEFAULT_INITIALIZED", "system", "", map[string]interface{}{"feed_id": DefaultIPFeedID, "changed": changed})
	}
	return err
}
func appendFeedID(ids []string, id string) []string {
	result := append([]string(nil), ids...)
	for _, existing := range result {
		if existing == id {
			return result
		}
	}
	return append(result, id)
}
func applyDefaultRulePolicy(ctx context.Context, tx pgx.Tx, rule BypassRule, policy RulePolicy) (RulePolicy, error) {
	if !rule.Allows() || policy.DefaultFeedConfigured {
		return policy, nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ip_feeds WHERE id=$1)", DefaultIPFeedID).Scan(&exists); err != nil {
		return RulePolicy{}, err
	}
	if exists {
		policy.BlockedFeedIDs = appendFeedID(policy.BlockedFeedIDs, DefaultIPFeedID)
		policy.DefaultFeedConfigured = true
	}
	return policy, nil
}
