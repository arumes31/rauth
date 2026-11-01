package core

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

const (
	CountryAll      = "all"
	CountrySelected = "selected"
)

// RulePolicy restricts the winning URL rule before session authorization.
// Zero values preserve the behavior of rules created before policies existed.
type RulePolicy struct {
	CountryMode          string   `json:"country_mode,omitempty"`
	AllowedCountries     []string `json:"allowed_countries,omitempty"`
	AllowPrivateNetworks bool     `json:"allow_private_networks,omitempty"`
	BlockedFeedIDs       []string `json:"blocked_feed_ids,omitempty"`
}

type CountryOption struct{ Code, Name string }

var policyCountries = buildPolicyCountries()

func buildPolicyCountries() []CountryOption {
	var out []CountryOption
	names := display.English.Regions()
	for a := 'A'; a <= 'Z'; a++ {
		for b := 'A'; b <= 'Z'; b++ {
			code := string([]rune{a, b})
			region, err := language.ParseRegion(code)
			if err == nil && region.IsCountry() && !region.IsPrivateUse() && region.String() == code {
				out = append(out, CountryOption{code, names.Name(region)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func PolicyCountries() []CountryOption { return append([]CountryOption(nil), policyCountries...) }

func NormalizeRulePolicy(p RulePolicy) (RulePolicy, error) {
	p.CountryMode = strings.ToLower(strings.TrimSpace(p.CountryMode))
	if p.CountryMode == "" {
		p.CountryMode = CountryAll
	}
	if p.CountryMode != CountryAll && p.CountryMode != CountrySelected {
		return RulePolicy{}, errors.New("country mode must be all or selected")
	}
	if len(p.AllowedCountries) > len(policyCountries) {
		return RulePolicy{}, errors.New("too many selected countries")
	}
	selected := map[string]bool{}
	for _, raw := range p.AllowedCountries {
		code := strings.ToUpper(strings.TrimSpace(raw))
		valid := false
		for _, option := range policyCountries {
			if option.Code == code {
				valid = true
				break
			}
		}
		if !valid {
			return RulePolicy{}, fmt.Errorf("invalid country code %q", raw)
		}
		selected[code] = true
	}
	p.AllowedCountries = nil
	if p.CountryMode == CountrySelected {
		if len(selected) == 0 {
			return RulePolicy{}, errors.New("select at least one allowed country")
		}
		for code := range selected {
			p.AllowedCountries = append(p.AllowedCountries, code)
		}
		sort.Strings(p.AllowedCountries)
	}
	// Feed references become configurable when the feed registry is available.
	// Never accept references that cannot yet be validated.
	if len(p.BlockedFeedIDs) > 0 {
		return RulePolicy{}, errors.New("IP feed registry is not available")
	}
	return p, nil
}

func (p RulePolicy) Restricted() bool {
	return (p.CountryMode != "" && p.CountryMode != CountryAll) || len(p.BlockedFeedIDs) > 0
}

func (p RulePolicy) CountrySummary() string {
	if p.CountryMode == "" || p.CountryMode == CountryAll {
		return "All countries"
	}
	out := "Only " + strings.Join(p.AllowedCountries, ", ")
	if p.AllowPrivateNetworks {
		out += "; private networks allowed"
	}
	return out
}

// PolicyDecision describes authorization restrictions, not application status.
type PolicyDecision struct {
	Allowed bool
	Reason  string
}

func (p RulePolicy) Evaluate(clientIP, country string) PolicyDecision {
	if len(p.BlockedFeedIDs) > 0 {
		return PolicyDecision{false, "ip_feed_unavailable"}
	}
	if p.CountryMode == "" || p.CountryMode == CountryAll {
		return PolicyDecision{true, ""}
	}
	if p.CountryMode != CountrySelected {
		return PolicyDecision{false, "policy_invalid"}
	}
	ip, err := netip.ParseAddr(clientIP)
	if err != nil || ip.Zone() != "" {
		return PolicyDecision{false, "invalid_client_ip"}
	}
	ip = ip.Unmap()
	private := ip.IsPrivate() || ip.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
	if private {
		if p.AllowPrivateNetworks {
			return PolicyDecision{true, ""}
		}
		return PolicyDecision{false, "country_blocked"}
	}
	for _, allowed := range p.AllowedCountries {
		if strings.EqualFold(allowed, country) {
			return PolicyDecision{true, ""}
		}
	}
	return PolicyDecision{false, "country_blocked"}
}

func HasRestrictedBypassRules() bool {
	set := activeBypass.Load()
	for _, list := range [][]BypassRule{set.env, set.ui} {
		for _, rule := range list {
			if rule.RulePolicy.Restricted() {
				return true
			}
		}
	}
	return false
}

func (p RulePolicy) CountryCodes() string { return strings.Join(p.AllowedCountries, ",") }

// HasRestrictedBypassRulesForHost limits policy enforcement to a known target.
// Reading a claimed host here can only cause a denial; allowing a public rule
// still requires trusted, overwritten proxy metadata.
func HasRestrictedBypassRulesForHost(rawHost string) bool {
	host := normalizeRequestHost(rawHost)
	if host == "" {
		return false
	}
	set := activeBypass.Load()
	for _, list := range [][]BypassRule{set.env, set.ui} {
		for _, rule := range list {
			if rule.matchesHost(host) && rule.RulePolicy.Restricted() {
				return true
			}
		}
	}
	return false
}
