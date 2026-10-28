package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// Auth bypass rules let selected hosts, or paths on a host, through the
// forward-auth check without a session (anonymous access). They are configured
// in the admin UI (stored in Postgres) and optionally via AUTH_BYPASS_RULES
// (read-only in the UI). Rule syntax:
//
//	cloud.example.com          every request to that host (same as cloud.example.com/*)
//	*.public.example.com       every request to any subdomain of public.example.com
//	web.example.com/           only the root page "/" of that host
//	web.example.com/webhook    /webhook and everything below it (same as /webhook/*)
//	!web.example.com/admin     deny: /admin and below always require login
//
// A rule either allows anonymous access ("allow") or explicitly requires login
// ("deny"). When several rules match a request, the most specific one wins:
// an exact host beats a wildcard (longer wildcard suffixes beat shorter ones),
// then an exact path ("/") beats a prefix, and a longer prefix beats a shorter
// one. On a tie, deny wins. So "host/", "!host/example" and "host/*" together
// open the whole host except /example and below.
//
// The requested host and URI come from headers the reverse proxy sets on the
// auth subrequest (AUTH_BYPASS_HOST_HEADER / AUTH_BYPASS_URI_HEADER). The proxy
// MUST overwrite those headers, otherwise a client could forge them. Matching
// fails closed: missing headers, unparseable values or paths that could be
// reinterpreted by a backend (dot segments, encoded slashes, backslashes, ';')
// never bypass.

// Bypass rule actions.
const (
	BypassAllow = "allow"
	BypassDeny  = "deny"
)

// BypassRule is one normalized bypass rule.
type BypassRule struct {
	// Rule is the canonical text form ("host", "host/" or "host/path"),
	// without the "!" deny marker.
	Rule string `json:"rule"`
	// Host is the lowercase host (without the "*." prefix for wildcards).
	Host string `json:"-"`
	// Wildcard matches subdomains of Host (not Host itself).
	Wildcard bool `json:"-"`
	// Path is the prefix ("" means the whole host); never ends with "/"
	// unless Exact is set, in which case it is "/".
	Path string `json:"-"`
	// Exact matches only the request path equal to Path (the root page).
	Exact bool `json:"-"`
	// Action is BypassAllow (anonymous access) or BypassDeny (login required).
	Action string `json:"action,omitempty"`
	// Source is "ui" (Redis, editable) or "env" (AUTH_BYPASS_RULES, read-only).
	Source    string `json:"source"`
	Note      string `json:"note,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// Allows reports whether the rule grants anonymous access.
func (r BypassRule) Allows() bool { return r.Action != BypassDeny }

// maxBypassRules bounds the rule set (it is scanned on every forward-auth call).
const maxBypassRules = 200

// maxBypassNote bounds the free-text note stored with a rule.
const maxBypassNote = 200

var (
	errBypassEmpty    = errors.New("rule is empty")
	errBypassHost     = errors.New("invalid host: use a hostname like app.example.com or *.example.com (no scheme or port)")
	errBypassPath     = errors.New("invalid path: must start with /, may only end in /*, and must not contain '..', '.', '%', '\\', ';', '?', '#' or other '*'")
	errBypassAction   = errors.New("invalid action: must be allow or deny")
	errBypassTooMany  = fmt.Errorf("too many rules (maximum %d)", maxBypassRules)
	errBypassExists   = errors.New("a rule for this host and path already exists; edit it instead")
	ErrBypassNotFound = errors.New("rule not found (rules from AUTH_BYPASS_RULES can only be changed in the environment)")
)

// ParseBypassRule validates and normalizes a rule such as "web.example.com/webhook".
// A leading "!" makes it a deny rule.
func ParseBypassRule(raw string) (BypassRule, error) {
	s := strings.TrimSpace(raw)
	r := BypassRule{Action: BypassAllow}
	if strings.HasPrefix(s, "!") {
		r.Action = BypassDeny
		s = strings.TrimSpace(s[1:])
	}
	if s == "" {
		return BypassRule{}, errBypassEmpty
	}
	if strings.Contains(s, "://") {
		return BypassRule{}, errBypassHost
	}
	hostPart, pathPart := s, ""
	if i := strings.Index(s, "/"); i >= 0 {
		hostPart, pathPart = s[:i], s[i:]
	}

	host := strings.TrimSuffix(strings.ToLower(hostPart), ".")
	if strings.HasPrefix(host, "*.") {
		r.Wildcard = true
		host = host[2:]
	}
	if !validHostname(host) {
		return BypassRule{}, errBypassHost
	}
	r.Host = host

	if pathPart != "" {
		p, exact, ok := normalizeRulePath(pathPart)
		if !ok {
			return BypassRule{}, errBypassPath
		}
		r.Path, r.Exact = p, exact
	}

	r.Rule = host
	if r.Wildcard {
		r.Rule = "*." + host
	}
	r.Rule += r.Path
	return r, nil
}

// normalizeAction maps a form value to a rule action; "" means allow.
func normalizeAction(a string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "", BypassAllow:
		return BypassAllow, nil
	case BypassDeny:
		return BypassDeny, nil
	}
	return "", errBypassAction
}

// validHostname accepts DNS hostnames (letters, digits, hyphens, dots); IP
// literals, ports and wildcards in other positions are rejected.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// normalizeRulePath validates a configured path. "/" alone means only the root
// page (exact=true). "/*" means the whole host (""), and a trailing "/*" or "/"
// on a longer path is dropped because prefixes already cover everything below.
func normalizeRulePath(p string) (string, bool, bool) {
	if p == "/" {
		return "/", true, true
	}
	p = strings.TrimSuffix(p, "*")
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "%\\;?#*") {
		return "", false, false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false, false
		}
	}
	cleaned := path.Clean(p)
	if cleaned == "/" {
		return "", false, true
	}
	return cleaned, false, true
}

// safeRequestPath turns the URI reported by the proxy into a normalized path
// for matching. It refuses (ok=false) anything a backend might resolve
// differently from rauth: dot segments, encoded or literal backslashes,
// encoded slashes, NUL, ';' path parameters, double encoding ("%25", which a
// second decoding pass downstream could turn into "%2e"/"%2f") and
// unparseable escapes.
func safeRequestPath(uri string) (string, bool) {
	if uri == "" {
		return "", false
	}
	// Strip query and fragment first so a URL inside the query string can
	// never be mistaken for the request target.
	if k := strings.IndexAny(uri, "?#"); k >= 0 {
		uri = uri[:k]
	}
	// Absolute-form request targets (http://host/path) carry the path after
	// the authority. Only a target that starts with the scheme counts.
	lowerURI := strings.ToLower(uri)
	for _, scheme := range []string{"http://", "https://"} {
		if strings.HasPrefix(lowerURI, scheme) {
			rest := uri[len(scheme):]
			if j := strings.Index(rest, "/"); j >= 0 {
				uri = rest[j:]
			} else {
				uri = "/"
			}
			break
		}
	}
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") || strings.ContainsAny(uri, "\\;") {
		return "", false
	}
	lower := strings.ToLower(uri)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") || strings.Contains(lower, "%2e") || strings.Contains(lower, "%25") {
		return "", false
	}
	decoded, err := url.PathUnescape(uri)
	if err != nil || strings.ContainsAny(decoded, "\\\x00;") {
		return "", false
	}
	for _, seg := range strings.Split(decoded, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return path.Clean(decoded), true
}

// normalizeRequestHost lowercases the reported host and strips a port and a
// trailing dot. It returns "" for anything that is not a valid hostname.
func normalizeRequestHost(h string) string {
	h = strings.TrimSpace(h)
	// X-Forwarded-Host may carry a list when several proxies append to it;
	// the first entry is the original host requested by the client.
	if i := strings.Index(h, ","); i >= 0 {
		h = strings.TrimSpace(h[:i])
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if !validHostname(h) {
		return ""
	}
	return h
}

func (r BypassRule) matches(host, reqPath string) bool {
	if r.Wildcard {
		if !strings.HasSuffix(host, "."+r.Host) {
			return false
		}
	} else if host != r.Host {
		return false
	}
	if r.Exact {
		return reqPath == r.Path
	}
	if r.Path == "" {
		return true
	}
	return reqPath == r.Path || strings.HasPrefix(reqPath, r.Path+"/")
}

// moreSpecific reports whether r should win over other when both match.
func (r BypassRule) moreSpecific(other BypassRule) bool {
	if r.Wildcard != other.Wildcard {
		return !r.Wildcard
	}
	if r.Wildcard && len(r.Host) != len(other.Host) {
		return len(r.Host) > len(other.Host)
	}
	if r.Exact != other.Exact {
		return r.Exact
	}
	if len(r.Path) != len(other.Path) {
		return len(r.Path) > len(other.Path)
	}
	return !r.Allows() && other.Allows()
}

// --- rule set cache -------------------------------------------------------

type bypassSet struct {
	env []BypassRule
	ui  []BypassRule
}

var activeBypass atomic.Pointer[bypassSet]

func init() {
	activeBypass.Store(&bypassSet{})
}

// MatchBypass returns the most specific rule matching the given host and URI,
// as reported by the reverse proxy, and whether it allows anonymous access.
// It fails closed on anything unclear.
func MatchBypass(rawHost, rawURI string) (BypassRule, bool) {
	set := activeBypass.Load()
	if len(set.env) == 0 && len(set.ui) == 0 {
		return BypassRule{}, false
	}
	host := normalizeRequestHost(rawHost)
	if host == "" {
		return BypassRule{}, false
	}
	reqPath, ok := safeRequestPath(rawURI)
	if !ok {
		return BypassRule{}, false
	}
	var best BypassRule
	found := false
	for _, list := range [][]BypassRule{set.env, set.ui} {
		for _, r := range list {
			if r.matches(host, reqPath) && (!found || r.moreSpecific(best)) {
				best, found = r, true
			}
		}
	}
	if !found {
		return BypassRule{}, false
	}
	return best, best.Allows()
}

// HasBypassRules reports whether any allow rule is active (deny rules alone
// never open anything).
func HasBypassRules() bool {
	set := activeBypass.Load()
	for _, list := range [][]BypassRule{set.env, set.ui} {
		for _, r := range list {
			if r.Allows() {
				return true
			}
		}
	}
	return false
}

// ListBypassRules returns all active rules: env rules first, then UI rules
// sorted by rule text.
func ListBypassRules() []BypassRule {
	set := activeBypass.Load()
	out := make([]BypassRule, 0, len(set.env)+len(set.ui))
	out = append(out, set.env...)
	out = append(out, set.ui...)
	return out
}

// SetEnvBypassRules parses AUTH_BYPASS_RULES; invalid entries are logged and
// skipped (fail closed).
func SetEnvBypassRules(raw []string) {
	var rules []BypassRule
	for _, s := range raw {
		r, err := ParseBypassRule(s)
		if err != nil {
			slog.Error("Ignoring invalid AUTH_BYPASS_RULES entry", "rule", s, "error", err)
			continue
		}
		r.Source = "env"
		rules = append(rules, r)
	}
	cur := activeBypass.Load()
	activeBypass.Store(&bypassSet{env: rules, ui: cur.ui})
	if len(rules) > 0 {
		slog.Warn("Auth bypass rules from AUTH_BYPASS_RULES are active; matching requests skip authentication", "rules", ruleTexts(rules))
	}
}

// ReloadBypassRules refreshes the UI-managed rules from the database. On error
// the previous set is kept.
func ReloadBypassRules() error {
	// bypass_rules holds the canonical rule text and its JSON metadata
	// (action, note, audit fields).
	rows, err := PG.Query(Ctx, "SELECT rule, meta FROM bypass_rules")
	if err != nil {
		return err
	}
	vals := map[string][]byte{}
	for rows.Next() {
		var rule string
		var meta []byte
		if err := rows.Scan(&rule, &meta); err != nil {
			rows.Close()
			return err
		}
		vals[rule] = meta
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rules := make([]BypassRule, 0, len(vals))
	for field, meta := range vals {
		r, err := ParseBypassRule(field)
		if err != nil || strings.HasPrefix(field, "!") {
			slog.Error("Ignoring invalid stored bypass rule", "rule", field, "error", err)
			continue
		}
		var m BypassRule
		_ = json.Unmarshal(meta, &m)
		action, err := normalizeAction(m.Action)
		if err != nil {
			// Unknown action: fail closed rather than open the path.
			action = BypassDeny
		}
		r.Action = action
		r.Source = "ui"
		r.Note, r.CreatedBy, r.CreatedAt = m.Note, m.CreatedBy, m.CreatedAt
		r.UpdatedBy, r.UpdatedAt = m.UpdatedBy, m.UpdatedAt
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Rule < rules[j].Rule })
	cur := activeBypass.Load()
	activeBypass.Store(&bypassSet{env: cur.env, ui: rules})
	return nil
}

// StartBypassRefresher loads the UI rules now and every interval, so all
// instances pick up changes made on another one.
func StartBypassRefresher(ctx context.Context, interval time.Duration) {
	if err := ReloadBypassRules(); err != nil {
		slog.Error("Failed to load auth bypass rules", "error", err)
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := ReloadBypassRules(); err != nil {
					slog.Error("Failed to refresh auth bypass rules, keeping previous set", "error", err)
				}
			}
		}
	}()
}

// parseRuleInput parses the rule text and action from the admin UI. The
// action field wins over a "!" prefix in the rule text only when it says deny.
func parseRuleInput(raw, action string) (BypassRule, error) {
	r, err := ParseBypassRule(raw)
	if err != nil {
		return BypassRule{}, err
	}
	a, err := normalizeAction(action)
	if err != nil {
		return BypassRule{}, err
	}
	if a == BypassDeny {
		r.Action = BypassDeny
	}
	return r, nil
}

func trimNote(note string) string {
	note = strings.TrimSpace(note)
	if len(note) > maxBypassNote {
		note = note[:maxBypassNote]
	}
	return note
}

func reloadAfter(op string) {
	if err := ReloadBypassRules(); err != nil {
		slog.Error("Failed to reload auth bypass rules after "+op, "error", err)
	}
}

// AddBypassRule stores a new UI-managed rule and reloads the active set. An
// existing rule for the same host and path is not overwritten.
func AddBypassRule(raw, action, note, createdBy string) (BypassRule, error) {
	r, err := parseRuleInput(raw, action)
	if err != nil {
		return BypassRule{}, err
	}
	var n int
	if err := PG.QueryRow(Ctx, "SELECT count(*) FROM bypass_rules").Scan(&n); err != nil {
		return BypassRule{}, err
	}
	if n >= maxBypassRules {
		return BypassRule{}, errBypassTooMany
	}
	meta, _ := json.Marshal(BypassRule{Action: r.Action, Note: trimNote(note), CreatedBy: createdBy, CreatedAt: time.Now().Unix()})
	tag, err := PG.Exec(Ctx, "INSERT INTO bypass_rules (rule, meta) VALUES ($1, $2) ON CONFLICT (rule) DO NOTHING", r.Rule, meta)
	if err != nil {
		return BypassRule{}, err
	}
	if tag.RowsAffected() == 0 {
		return BypassRule{}, errBypassExists
	}
	reloadAfter("add")
	return r, nil
}

// UpdateBypassRule changes the rule text, action and note of a UI-managed
// rule, keeping its creation metadata. It returns the old and new rule.
func UpdateBypassRule(oldRaw, newRaw, action, note, updatedBy string) (BypassRule, BypassRule, error) {
	old, err := ParseBypassRule(oldRaw)
	if err != nil {
		return BypassRule{}, BypassRule{}, err
	}
	r, err := parseRuleInput(newRaw, action)
	if err != nil {
		return BypassRule{}, BypassRule{}, err
	}
	err = pgx.BeginFunc(Ctx, PG, func(tx pgx.Tx) error {
		var prevMeta []byte
		err := tx.QueryRow(Ctx, "SELECT meta FROM bypass_rules WHERE rule = $1 FOR UPDATE", old.Rule).Scan(&prevMeta)
		if isNoRows(err) {
			return ErrBypassNotFound
		} else if err != nil {
			return err
		}
		var prev BypassRule
		_ = json.Unmarshal(prevMeta, &prev)
		old.Action, _ = normalizeAction(prev.Action)

		meta, _ := json.Marshal(BypassRule{
			Action: r.Action, Note: trimNote(note),
			CreatedBy: prev.CreatedBy, CreatedAt: prev.CreatedAt,
			UpdatedBy: updatedBy, UpdatedAt: time.Now().Unix(),
		})
		if r.Rule == old.Rule {
			_, err := tx.Exec(Ctx, "UPDATE bypass_rules SET meta = $2 WHERE rule = $1", r.Rule, meta)
			return err
		}
		tag, err := tx.Exec(Ctx, "INSERT INTO bypass_rules (rule, meta) VALUES ($1, $2) ON CONFLICT (rule) DO NOTHING", r.Rule, meta)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errBypassExists
		}
		_, err = tx.Exec(Ctx, "DELETE FROM bypass_rules WHERE rule = $1", old.Rule)
		return err
	})
	if err != nil {
		return BypassRule{}, BypassRule{}, err
	}
	reloadAfter("update")
	return old, r, nil
}

// DeleteBypassRule removes a UI-managed rule and reloads the active set. It
// reports whether the rule existed.
func DeleteBypassRule(raw string) (bool, error) {
	r, err := ParseBypassRule(raw)
	if err != nil {
		return false, err
	}
	tag, err := PG.Exec(Ctx, "DELETE FROM bypass_rules WHERE rule = $1", r.Rule)
	if err != nil {
		return false, err
	}
	reloadAfter("delete")
	return tag.RowsAffected() > 0, nil
}

// DescribeBypassRule renders the rule scope for the admin UI.
func DescribeBypassRule(r BypassRule) string {
	target := r.Host
	if r.Wildcard {
		target = "any subdomain of " + r.Host
	}
	var scope string
	switch {
	case r.Exact:
		scope = "Only the root page / of " + target
	case r.Path == "":
		scope = "All requests to " + target
	default:
		scope = r.Path + " and below on " + target
	}
	if r.Allows() {
		return scope + ": public"
	}
	return scope + ": login required"
}

func ruleTexts(rules []BypassRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		if r.Allows() {
			out[i] = r.Rule
		} else {
			out[i] = "!" + r.Rule
		}
	}
	return out
}
