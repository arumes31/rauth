package core

import "net"

// IsTrustedProxyPeer applies the same direct-peer boundary to forwarded
// metadata used for bypass decisions and the administration request feed.
func (cfg *Config) IsTrustedProxyPeer(remoteAddr string) bool {
	if cfg == nil {
		return false
	}
	peer, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		peer = remoteAddr
	}
	if len(cfg.TrustedProxies) > 0 {
		return cfg.IsIPAllowed(peer, cfg.TrustedProxies)
	}
	ip := net.ParseIP(peer)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback())
}
