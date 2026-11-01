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
	DefaultFeedConfigured bool     `json:"default_feed_configured,omitempty"`
	CountryMode           string   `json:"country_mode,omitempty"`
	AllowedCountries      []string `json:"allowed_countries,omitempty"`
	AllowPrivateNetworks  bool     `json:"allow_private_networks,omitempty"`
	BlockedFeedIDs        []string `json:"blocked_feed_ids,omitempty"`
}

type CountryOption struct{ Code, Name string }

var policyCountries = buildPolicyCountries()

// Deprecated alpha-2 aliases from Unicode CLDR territoryAlias. Some split
// territories (for example SU) cannot be canonicalized to a single successor.
const obsoleteCountryAliases = " AN BU CS CT DD DY FQ FX HV JT MI NH NQ NT PC PU PZ QU RH SU TP UK VD WK YD YU ZR "

func buildPolicyCountries() []CountryOption {
	var out []CountryOption
	names := display.English.Regions()
	for a := 'A'; a <= 'Z'; a++ {
		for b := 'A'; b <= 'Z'; b++ {
			code := string([]rune{a, b})
			region, err := language.ParseRegion(code)
			if !strings.Contains(obsoleteCountryAliases, " "+code+" ") && err == nil && region.IsCountry() && !region.IsPrivateUse() && region.String() == code && region.Canonicalize() == region {
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
	ids, err := normalizeFeedIDs(p.BlockedFeedIDs)
	if err != nil {
		return RulePolicy{}, err
	}
	p.BlockedFeedIDs = ids
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
	FeedID  string
}

func (p RulePolicy) Evaluate(clientIP, country string) PolicyDecision {
	if len(p.BlockedFeedIDs) > 0 {
		ip, err := netip.ParseAddr(clientIP)
		if err != nil || ip.Zone() != "" {
			return PolicyDecision{Allowed: false, Reason: "invalid_client_ip"}
		}
		result := matchPolicyFeeds(p.BlockedFeedIDs, ip.Unmap())
		if !result.Allowed {
			return result
		}
	}
	if p.CountryMode == "" || p.CountryMode == CountryAll {
		return PolicyDecision{Allowed: true}
	}
	if p.CountryMode != CountrySelected {
		return PolicyDecision{Allowed: false, Reason: "policy_invalid"}
	}
	ip, err := netip.ParseAddr(clientIP)
	if err != nil || ip.Zone() != "" {
		return PolicyDecision{Allowed: false, Reason: "invalid_client_ip"}
	}
	ip = ip.Unmap()
	private := ip.IsPrivate() || ip.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
	if private {
		if p.AllowPrivateNetworks {
			return PolicyDecision{Allowed: true}
		}
		return PolicyDecision{Allowed: false, Reason: "country_blocked"}
	}
	for _, allowed := range p.AllowedCountries {
		if strings.EqualFold(allowed, country) {
			return PolicyDecision{Allowed: true}
		}
	}
	return PolicyDecision{Allowed: false, Reason: "country_blocked"}
}

func HasRestrictedBypassRules() bool {
	set := activeBypass.Load()
	for _, list := range [][]BypassRule{set.env, set.ui} {
		for _, rule := range list {
			if rule.Restricted() {
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
			if rule.matchesHost(host) && rule.Restricted() {
				return true
			}
		}
	}
	return false
}

func (p RulePolicy) FeedCodes() string { return strings.Join(p.BlockedFeedIDs, ",") }
