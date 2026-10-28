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
)

// Auth bypass rules let selected hosts, or path prefixes on a host, through the
// forward-auth check without a session (anonymous access). They are configured
// in the admin UI (stored in Redis) and optionally via AUTH_BYPASS_RULES
// (read-only in the UI). Rule syntax:
//
//	cloud.example.com          every request to that host
//	*.public.example.com       every request to any subdomain of public.example.com
//	web.example.com/webhook    /webhook and everything below it on that host
//
// The requested host and URI come from headers the reverse proxy sets on the
// auth subrequest (AUTH_BYPASS_HOST_HEADER / AUTH_BYPASS_URI_HEADER). The proxy
// MUST overwrite those headers, otherwise a client could forge them. Matching
// fails closed: missing headers, unparseable values or paths that could be
// reinterpreted by a backend (dot segments, encoded slashes, backslashes, ';')
// never bypass.

// BypassRule is one normalized bypass rule.
type BypassRule struct {
	// Rule is the canonical text form ("host" or "host/path").
	Rule string `json:"rule"`
	// Host is the lowercase host (without the "*." prefix for wildcards).
	Host string `json:"-"`
	// Wildcard matches subdomains of Host (not Host itself).
	Wildcard bool `json:"-"`
	// Path is the prefix ("" means the whole host); never ends with "/".
	Path string `json:"-"`
	// Source is "ui" (Redis, editable) or "env" (AUTH_BYPASS_RULES, read-only).
	Source    string `json:"source"`
	Note      string `json:"note,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
}

// bypassRulesKey is the Redis hash (UserDB) holding UI-managed rules:
// field = canonical rule, value = JSON metadata.
const bypassRulesKey = "auth_bypass_rules"

// maxBypassRules bounds the rule set (it is scanned on every forward-auth call).
const maxBypassRules = 200

// maxBypassNote bounds the free-text note stored with a rule.
const maxBypassNote = 200

var (
	errBypassEmpty   = errors.New("rule is empty")
	errBypassHost    = errors.New("invalid host: use a hostname like app.example.com or *.example.com (no scheme or port)")
	errBypassPath    = errors.New("invalid path: must start with / and must not contain '..', '.', '%', '\\', ';', '?' or '#' segments")
	errBypassTooMany = fmt.Errorf("too many rules (maximum %d)", maxBypassRules)
)

// ParseBypassRule validates and normalizes a rule such as "web.example.com/webhook".
func ParseBypassRule(raw string) (BypassRule, error) {
	s := strings.TrimSpace(raw)
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

	r := BypassRule{}
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
		p, ok := normalizeRulePath(pathPart)
		if !ok {
			return BypassRule{}, errBypassPath
		}
		r.Path = p
	}

	r.Rule = host
	if r.Wildcard {
		r.Rule = "*." + host
	}
	r.Rule += r.Path
	return r, nil
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
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// normalizeRulePath validates a configured path prefix. "/" (or a trailing
// slash) is normalized away, so "/" means the whole host.
func normalizeRulePath(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "%\\;?#") {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	cleaned := path.Clean(p)
	if cleaned == "/" {
		return "", true
	}
	return cleaned, true
}

// safeRequestPath turns the URI reported by the proxy into a normalized path
// for matching. It refuses (ok=false) anything a backend might resolve
// differently from rauth: dot segments, encoded or literal backslashes,
// encoded slashes, NUL, ';' path parameters and unparseable escapes.
func safeRequestPath(uri string) (string, bool) {
	if uri == "" {
		return "", false
	}
	// Absolute-form request targets (http://host/path) carry the path after the authority.
	if i := strings.Index(uri, "://"); i >= 0 {
		rest := uri[i+3:]
		j := strings.Index(rest, "/")
		if j < 0 {
			return "/", true
		}
		uri = rest[j:]
	}
	if k := strings.IndexAny(uri, "?#"); k >= 0 {
		uri = uri[:k]
	}
	if uri == "" {
		uri = "/"
	}
	if !strings.HasPrefix(uri, "/") || strings.ContainsAny(uri, "\\;") {
		return "", false
	}
	lower := strings.ToLower(uri)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") || strings.Contains(lower, "%2e") {
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
	if r.Path == "" {
		return true
	}
	return reqPath == r.Path || strings.HasPrefix(reqPath, r.Path+"/")
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

// MatchBypass reports the first rule matching the given host and URI, as
// reported by the reverse proxy. It fails closed on anything unclear.
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
	for _, list := range [][]BypassRule{set.env, set.ui} {
		for _, r := range list {
			if r.matches(host, reqPath) {
				return r, true
			}
		}
	}
	return BypassRule{}, false
}

// HasBypassRules reports whether any bypass rule is active.
func HasBypassRules() bool {
	set := activeBypass.Load()
	return len(set.env) > 0 || len(set.ui) > 0
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

// ReloadBypassRules refreshes the UI-managed rules from Redis. On error the
// previous set is kept.
func ReloadBypassRules() error {
	vals, err := UserDB.HGetAll(Ctx, bypassRulesKey).Result()
	if err != nil {
		return err
	}
	rules := make([]BypassRule, 0, len(vals))
	for field, meta := range vals {
		r, err := ParseBypassRule(field)
		if err != nil {
			slog.Error("Ignoring invalid stored bypass rule", "rule", field, "error", err)
			continue
		}
		var m BypassRule
		_ = json.Unmarshal([]byte(meta), &m)
		r.Source = "ui"
		r.Note, r.CreatedBy, r.CreatedAt = m.Note, m.CreatedBy, m.CreatedAt
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

// AddBypassRule stores a UI-managed rule and reloads the active set.
func AddBypassRule(raw, note, createdBy string) (BypassRule, error) {
	r, err := ParseBypassRule(raw)
	if err != nil {
		return BypassRule{}, err
	}
	note = strings.TrimSpace(note)
	if len(note) > maxBypassNote {
		note = note[:maxBypassNote]
	}
	n, err := UserDB.HLen(Ctx, bypassRulesKey).Result()
	if err != nil {
		return BypassRule{}, err
	}
	if n >= maxBypassRules {
		return BypassRule{}, errBypassTooMany
	}
	meta, _ := json.Marshal(BypassRule{Note: note, CreatedBy: createdBy, CreatedAt: time.Now().Unix()})
	if err := UserDB.HSet(Ctx, bypassRulesKey, r.Rule, meta).Err(); err != nil {
		return BypassRule{}, err
	}
	if err := ReloadBypassRules(); err != nil {
		slog.Error("Failed to reload auth bypass rules after add", "error", err)
	}
	return r, nil
}

// DeleteBypassRule removes a UI-managed rule and reloads the active set. It
// reports whether the rule existed.
func DeleteBypassRule(raw string) (bool, error) {
	r, err := ParseBypassRule(raw)
	if err != nil {
		return false, err
	}
	n, err := UserDB.HDel(Ctx, bypassRulesKey, r.Rule).Result()
	if err != nil {
		return false, err
	}
	if err := ReloadBypassRules(); err != nil {
		slog.Error("Failed to reload auth bypass rules after delete", "error", err)
	}
	return n > 0, nil
}

// DescribeBypassRule renders the rule scope for the admin UI.
func DescribeBypassRule(r BypassRule) string {
	target := r.Host
	if r.Wildcard {
		target = "any subdomain of " + r.Host
	}
	if r.Path == "" {
		return "All requests to " + target
	}
	return r.Path + " and below on " + target
}

func ruleTexts(rules []BypassRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Rule
	}
	return out
}
