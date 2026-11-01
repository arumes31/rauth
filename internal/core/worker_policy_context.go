package core

import "context"

type snapshotContextKey struct{}

// WithPolicySnapshot is used only inside a live worker.WithPolicy callback. Its
// caller must not let the context escape the callback or extend resource lifetime.
func WithPolicySnapshot(ctx context.Context, snapshot *PolicySnapshot) context.Context {
	return context.WithValue(ctx, snapshotContextKey{}, snapshot)
}
func PolicySnapshotFromContext(ctx context.Context) (*PolicySnapshot, bool) {
	if ctx == nil {
		return nil, false
	}
	snapshot, ok := ctx.Value(snapshotContextKey{}).(*PolicySnapshot)
	return snapshot, ok && snapshot != nil
}
func CountryCodeForContext(ctx context.Context, ip string) string {
	if snapshot, ok := PolicySnapshotFromContext(ctx); ok {
		return snapshot.CountryCode(ip)
	}
	return GetCountryCode(ip)
}
func SelectBypassRuleForContext(ctx context.Context, host, uri string) (BypassRule, bool, error) {
	if snapshot, ok := PolicySnapshotFromContext(ctx); ok {
		return snapshot.SelectRule(host, uri)
	}
	return SelectBypassRule(host, uri)
}
func HasBypassRulesForContext(ctx context.Context) bool {
	if snapshot, ok := PolicySnapshotFromContext(ctx); ok {
		return snapshot.HasRules()
	}
	return HasBypassRules()
}
func RestrictedBypassHostForContext(ctx context.Context, host string) bool {
	if snapshot, ok := PolicySnapshotFromContext(ctx); ok {
		return snapshot.RestrictedForHost(host)
	}
	return HasRestrictedBypassRulesForHost(host)
}
func MatchBypassForContext(ctx context.Context, host, uri string) (BypassRule, bool) {
	r, found, err := SelectBypassRuleForContext(ctx, host, uri)
	return r, err == nil && found && r.Allows()
}
func EvaluateRuleForContext(ctx context.Context, policy RulePolicy, ip string) PolicyDecision {
	if snapshot, ok := PolicySnapshotFromContext(ctx); ok {
		return snapshot.Evaluate(policy, ip)
	}
	return policy.Evaluate(ip, GetCountryCode(ip))
}
