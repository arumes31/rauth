package core

import (
	"bufio"
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

func parseCommonPasswords() {
	commonPasswords = make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(commonPasswordsRaw))
	for scanner.Scan() {
		p := strings.TrimSpace(scanner.Text())
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		commonPasswords[strings.ToLower(p)] = struct{}{}
	}
}

// InitCommonPasswords loads the embedded common-password blocklist and records
// whether the check is enabled. Safe to call multiple times; the parse runs once.
func InitCommonPasswords(enabled bool) {
	commonPasswordsOn = enabled
	commonPasswordsOnce.Do(parseCommonPasswords)
}

// isCommonPassword reports whether the password appears in the blocklist.
func isCommonPassword(password string) bool {
	if !commonPasswordsOn {
		return false
	}
	// Lazily parse so the check also works when callers (e.g. tests) skip InitCommonPasswords.
	commonPasswordsOnce.Do(parseCommonPasswords)
	_, found := commonPasswords[strings.ToLower(strings.TrimSpace(password))]
	return found
}
