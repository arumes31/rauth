package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Cloudflare edge ranges used to decide whether CF-Connecting-IP can be
// trusted. Seeded from DefaultCloudflareIPRanges (or CLOUDFLARE_IP_RANGES) and,
// when enabled, refreshed from Cloudflare's published lists at startup and
// daily. A failed or implausible refresh keeps the current list.

var cloudflareNets atomic.Pointer[[]*net.IPNet]

// cloudflareRangeURLs are Cloudflare's official plain-text edge lists.
var cloudflareRangeURLs = []string{
	"https://www.cloudflare.com/ips-v4",
	"https://www.cloudflare.com/ips-v6",
}

const (
	cloudflareRefreshInterval = 24 * time.Hour
	cloudflareFetchTimeout    = 15 * time.Second
	// cloudflareMaxBody bounds each downloaded list.
	cloudflareMaxBody = 64 << 10
	// cloudflareMinRanges rejects a truncated or bogus download.
	cloudflareMinRanges = 10
)

func init() {
	nets, _ := parseCIDRs(DefaultCloudflareIPRanges)
	cloudflareNets.Store(&nets)
}

// SetCloudflareRanges replaces the active edge list with valid CIDRs from
// ranges; invalid entries are logged and skipped. An empty result is ignored.
func SetCloudflareRanges(ranges []string) {
	nets, bad := parseCIDRs(ranges)
	for _, b := range bad {
		slog.Warn("Ignoring invalid Cloudflare IP range", "range", b)
	}
	if len(nets) == 0 {
		return
	}
	cloudflareNets.Store(&nets)
}

// IsCloudflareIP reports whether ip belongs to a Cloudflare edge network.
func IsCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range *cloudflareNets.Load() {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func parseCIDRs(ranges []string) ([]*net.IPNet, []string) {
	var nets []*net.IPNet
	var bad []string
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			bad = append(bad, r)
			continue
		}
		nets = append(nets, n)
	}
	return nets, bad
}

// StartCloudflareUpdater seeds the edge list from config and, when
// TRUST_CLOUDFLARE_IP and CLOUDFLARE_IP_AUTO_UPDATE are enabled, refreshes it
// from Cloudflare now and every 24h until ctx is cancelled.
func StartCloudflareUpdater(ctx context.Context, cfg *Config) {
	SetCloudflareRanges(cfg.CloudflareIPRanges)
	if !cfg.TrustCloudflareIP || !cfg.CloudflareAutoUpdate {
		return
	}
	go func() {
		refreshCloudflareRanges(ctx)
		ticker := time.NewTicker(cloudflareRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshCloudflareRanges(ctx)
			}
		}
	}()
}

func refreshCloudflareRanges(ctx context.Context) {
	ranges, err := fetchCloudflareRanges(ctx, http.DefaultClient, cloudflareRangeURLs)
	if err != nil {
		slog.Warn("Cloudflare IP range refresh failed, keeping current list", "error", err)
		return
	}
	SetCloudflareRanges(ranges)
	slog.Info("Cloudflare IP ranges refreshed", "count", len(ranges))
}

// fetchCloudflareRanges downloads and validates all lists. It fails if any list
// cannot be fetched, contains an invalid entry, or the total is implausibly small.
func fetchCloudflareRanges(ctx context.Context, client *http.Client, urls []string) ([]string, error) {
	var all []string
	for _, u := range urls {
		reqCtx, cancel := context.WithTimeout(ctx, cloudflareFetchTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, cloudflareMaxBody))
		_ = resp.Body.Close()
		cancel()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(line); err != nil {
				return nil, fmt.Errorf("%s: invalid range %q", u, line)
			}
			all = append(all, line)
		}
	}
	if len(all) < cloudflareMinRanges {
		return nil, fmt.Errorf("only %d ranges received", len(all))
	}
	return all, nil
}
