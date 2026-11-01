package core

import (
	"errors"
	"net/netip"
	"net/url"
)

type PolicyPreview struct {
	URL     string `json:"url"`
	Source  string `json:"source"`
	Country string `json:"country"`
	Rule    string `json:"rule"`
	Public  bool   `json:"public"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	FeedID  string `json:"feed_id,omitempty"`
}

func PreviewURLPolicy(rawURL, clientIP string) (PolicyPreview, error) {
	if len(rawURL) > 2048 {
		return PolicyPreview{}, errors.New("URL is too long")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return PolicyPreview{}, errors.New("enter an HTTP or HTTPS URL without credentials")
	}
	ip, err := netip.ParseAddr(clientIP)
	if err != nil || ip.Zone() != "" {
		return PolicyPreview{}, errors.New("enter a valid client IP address")
	}
	p := PolicyPreview{URL: ProtectedRequestURL(u.Scheme, u.Host, u.RequestURI()), Source: ip.Unmap().String(), Allowed: true}
	p.Country = GetCountryCode(p.Source)
	rule, found, err := SelectBypassRule(u.Host, u.RequestURI())
	if err != nil {
		p.Allowed = false
		p.Reason = "policy_target_invalid"
		return p, nil
	}
	if !found {
		p.Reason = "login_required"
		return p, nil
	}
	p.Rule = rule.Rule
	p.Public = rule.Allows()
	decision := rule.Evaluate(p.Source, p.Country)
	p.Allowed = decision.Allowed
	p.Reason = decision.Reason
	p.FeedID = decision.FeedID
	if p.Allowed {
		if p.Public {
			p.Reason = "public"
		} else {
			p.Reason = "login_required"
		}
	}
	return p, nil
}
