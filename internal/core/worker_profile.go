package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
)

// Every Config field is explicitly classified. New fields fail profile creation
// until reviewed, so a new credential cannot accidentally enter a public digest
// and a new security setting cannot silently evade version coordination.
const policySecurityFields = "AuthStateMode AuthStateAbsoluteMinutes SSOCanonicalOrigin SSOApplicationOrigins CookieDomains TokenValidityMinutes AllowedHosts MetricsAllowedIPs WebAuthnOrigins AllowedCountries MinPasswordLength RequirePasswordUpper RequirePasswordLower RequirePasswordNumber RequirePasswordSpecial SMTPHost SMTPPort SMTPUser SMTPFrom SMTPTLS PublicURL TokenRotationMinutes TrustCloudflareIP TrustXRealIP TrustXForwardedFor TrustedProxies CloudflareIPRanges CloudflareAutoUpdate RateLimitLoginMax RateLimitLoginDecay RateLimitRegistrationMax RateLimitRegistrationDecay RateLimitValidateMax RateLimitValidateDecay RateLimitLoginAccessMax RateLimitLoginAccessDecay RateLimitLoginFailUserMax RateLimitLoginFailUserDecay RateLimitLoginFailIPMax RateLimitLoginFailIPDecay BcryptCost CheckCommonPasswords GeoChangeMode WebAuthnRequireUserVerification CSRFTrustedOrigins AuthBypassRules AuthBypassHostHeader AuthBypassURIHeader RequestFeedIPHeader"
const policyOperationalFields = "ClusterConfigFile ListenAddr ServerSecret RedisHost RedisPort RedisPassword PostgresURL AuthStateKeyFile AuditRetentionDays GeoApiHost GeoApiPort MaxMindDBPath InitialUser InitialPassword InitialEmail Initial2FASecret MaxMindAccountID MaxMindLicenseKey MaxMindEditionIDs SMTPPass LogLevel"

func NodeSecurityFingerprint(cfg *Config) (string, error) {
	if cfg == nil {
		return "", errors.New("missing node configuration")
	}
	classes := map[string]bool{}
	for _, name := range strings.Fields(policySecurityFields) {
		classes[name] = true
	}
	for _, name := range strings.Fields(policyOperationalFields) {
		if _, exists := classes[name]; exists {
			return "", errors.New("duplicate configuration field classification")
		}
		classes[name] = false
	}
	projection := map[string]any{}
	value := reflect.ValueOf(cfg).Elem()
	kind := value.Type()
	for i := 0; i < kind.NumField(); i++ {
		name := kind.Field(i).Name
		security, known := classes[name]
		if !known {
			return "", fmt.Errorf("configuration field requires security classification: %s", name)
		}
		if security {
			projection[name] = value.Field(i).Interface()
		}
		delete(classes, name)
	}
	if len(classes) != 0 {
		return "", errors.New("classified configuration field no longer exists")
	}
	body, err := json.Marshal(projection)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("rauth-node-security-v1\x00"), body...))
	return hex.EncodeToString(sum[:]), nil
}

// WorkerPolicyOptionsForConfig freezes the expected profile only after the
// selected SQL/SSO authority and explicit proxy trust are valid. Deployment must
// measure Docker SNAT and enforce the source firewall before selecting peers.
func WorkerPolicyOptionsForConfig(nodeID string, cfg *Config) (WorkerPolicyOptions, error) {
	invalid := WorkerPolicyOptions{}
	if !policyUUID(nodeID) || cfg == nil {
		return invalid, errors.New("invalid policy node identity")
	}
	mode, err := configuredAuthStateMode(cfg)
	if err != nil || mode != "postgres" {
		return invalid, errors.New("worker policy runtime requires PostgreSQL authentication authority")
	}
	if cfg.SSOCanonicalOrigin == "" {
		return invalid, errors.New("worker policy runtime requires canonical SSO enrollment")
	}
	if err = cfg.ValidateSSO(); err != nil {
		return invalid, err
	}
	if cfg.CloudflareAutoUpdate {
		return invalid, errors.New("worker policy runtime requires versioned Cloudflare ranges; disable automatic config mutation")
	}
	if len(cfg.TrustedProxies) == 0 {
		return invalid, errors.New("worker policy runtime requires explicit proxy peers")
	}
	for _, raw := range cfg.TrustedProxies {
		ip, e := netip.ParseAddr(raw)
		if e != nil {
			prefix, parseErr := netip.ParsePrefix(raw)
			if parseErr != nil || prefix.Bits() != prefix.Addr().BitLen() {
				return invalid, errors.New("worker proxy trust must name individual IPs, not network ranges")
			}
			ip = prefix.Addr()
		}
		if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return invalid, errors.New("invalid worker proxy peer")
		}
	}
	if cfg.AuthBypassHostHeader == "" || cfg.AuthBypassURIHeader == "" {
		return invalid, errors.New("worker policy runtime requires target headers")
	}
	fingerprint, err := NodeSecurityFingerprint(cfg)
	if err != nil {
		return invalid, err
	}
	return WorkerPolicyOptions{NodeID: nodeID, SecurityFingerprint: fingerprint, RequireGeoIP: len(cfg.AllowedCountries) > 0}, nil
}
