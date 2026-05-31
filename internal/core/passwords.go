package core

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed common_passwords.txt
var commonPasswordsRaw string

var (
	commonPasswordsOnce sync.Once
	commonPasswords     map[string]struct{}
	commonPasswordsOn   = true
)

// InitCommonPasswords loads the embedded common-password blocklist and records
// whether the check is enabled. Safe to call multiple times; the parse runs once.
func InitCommonPasswords(enabled bool) {
	commonPasswordsOn = enabled
	commonPasswordsOnce.Do(func() {
		commonPasswords = make(map[string]struct{})
		for _, line := range strings.Split(commonPasswordsRaw, "\n") {
			p := strings.TrimSpace(line)
			if p == "" || strings.HasPrefix(p, "#") {
				continue
			}
			commonPasswords[strings.ToLower(p)] = struct{}{}
		}
	})
}

// isCommonPassword reports whether the password appears in the blocklist.
func isCommonPassword(password string) bool {
	if !commonPasswordsOn {
		return false
	}
	// Lazily parse so the check also works when callers (e.g. tests) skip InitCommonPasswords.
	commonPasswordsOnce.Do(func() {
		commonPasswords = make(map[string]struct{})
		for _, line := range strings.Split(commonPasswordsRaw, "\n") {
			p := strings.TrimSpace(line)
			if p == "" || strings.HasPrefix(p, "#") {
				continue
			}
			commonPasswords[strings.ToLower(p)] = struct{}{}
		}
	})
	_, found := commonPasswords[strings.ToLower(strings.TrimSpace(password))]
	return found
}
