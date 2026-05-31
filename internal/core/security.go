package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

	passwordUpperRegex   = regexp.MustCompile(`[A-Z]`)
	passwordLowerRegex   = regexp.MustCompile(`[a-z]`)
	passwordNumberRegex  = regexp.MustCompile(`[0-9]`)
	passwordSpecialRegex = regexp.MustCompile(`[!@#\$%\^&\*]`)
)

func ValidateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	if !emailRegex.MatchString(email) {
		return errors.New("invalid email format")
	}
	return nil
}

func ValidatePassword(password string, cfg *Config) error {
	if len(password) < cfg.MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", cfg.MinPasswordLength)
	}
	// bcrypt silently truncates input beyond 72 bytes, so anything longer would
	// have its suffix ignored. Reject it explicitly to avoid that surprise.
	if len(password) > 72 {
		return fmt.Errorf("password must be at most 72 bytes long")
	}
	if cfg.CheckCommonPasswords && isCommonPassword(password) {
		return fmt.Errorf("password is too common; please choose a less predictable one")
	}
	if cfg.RequirePasswordUpper && !passwordUpperRegex.MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if cfg.RequirePasswordLower && !passwordLowerRegex.MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if cfg.RequirePasswordNumber && !passwordNumberRegex.MatchString(password) {
		return fmt.Errorf("password must contain at least one number")
	}
	if cfg.RequirePasswordSpecial && !passwordSpecialRegex.MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}

// bcryptCost is the configurable work factor used by HashPassword. It is set
// once at startup via SetBcryptCost and read without locking thereafter.
var bcryptCost = 12

// SetBcryptCost applies a configured bcrypt cost, clamping it to the values
// bcrypt actually supports and falling back to a safe default otherwise.
func SetBcryptCost(cost int) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		slog.Warn("Invalid BCRYPT_COST, falling back to default", "requested", cost, "default", 12)
		cost = 12
	}
	bcryptCost = cost
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getAESKeyLegacy(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func getAESKey(key string) []byte {
	hash := sha256.New
	hk := hkdf.New(hash, []byte(key), nil, []byte("rauth-aes-key"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hk, derivedKey); err != nil {
		// This should never happen with HKDF unless there's a serious system failure
		panic(err)
	}
	return derivedKey
}

func EncryptToken(text string, key string) (string, error) {
	block, err := aes.NewCipher(getAESKey(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptToken(encryptedText string, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	// Try with the new KDF first
	plaintext, err := decryptWithKey(data, getAESKey(key))
	if err == nil {
		return plaintext, nil
	}

	// Fallback to legacy KDF (SHA256). Track successful legacy decrypts so the
	// fallback's continued necessity is observable before it is removed.
	legacyPlaintext, legacyErr := decryptWithKey(data, getAESKeyLegacy(key))
	if legacyErr == nil {
		LegacyKDFDecryptTotal.Inc()
	}
	return legacyPlaintext, legacyErr
}

func decryptWithKey(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func GenerateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func Encrypt2FASecret(secret string, key string) string {
	if secret == "" {
		return ""
	}
	encrypted, err := EncryptToken(secret, key)
	if err != nil {
		return secret
	} // Fallback to plain if encryption fails (should not happen)
	return "enc:" + encrypted
}

func Decrypt2FASecret(secret string, key string) string {
	if secret == "" {
		return ""
	}
	if !strings.HasPrefix(secret, "enc:") {
		return secret // Already plain
	}
	decrypted, err := DecryptToken(secret[4:], key)
	if err != nil {
		return secret // Fallback to plain/as-is if decryption fails
	}
	return decrypted
}

func FormatUserAgent(ua string) string {
	if ua == "" {
		return "Unknown Device"
	}
	parsed := ParseUserAgent(ua)
	details := fmt.Sprintf("%s on %s", parsed.Browser, parsed.OS)
	if parsed.Platform != "" {
		details += " (" + parsed.Platform + ")"
	}
	if parsed.IsMobile {
		details += " [Mobile]"
	}
	return details
}

func GetDeviceIcon(ua string) string {
	if strings.Contains(ua, "Android") {
		return "bi-android2"
	} else if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
		return "bi-apple"
	} else if strings.Contains(ua, "Windows") {
		return "bi-microsoft"
	} else if strings.Contains(ua, "Macintosh") {
		return "bi-apple"
	} else if strings.Contains(ua, "Linux") {
		return "bi-ubuntu"
	}
	return "bi-display"
}

// ValidateRedirectURL safely validates and sanitizes a redirect URL
func ValidateRedirectURL(rd, defaultRedirect, username string, cfg *Config) string {
	rd = strings.TrimSpace(rd)
	if rd == "" {
		return defaultRedirect
	}

	// Prevent protocol-relative redirects and potential browser normalisation bypasses (e.g., //evil.com, /\evil.com, \\evil.com, \evil.com)
	if strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") || strings.HasPrefix(rd, "\\") {
		slog.Warn("Protocol-relative redirect attempted", "url", rd, "user", username)
		return defaultRedirect
	}

	parsedURL, err := url.Parse(rd)
	if err != nil {
		return defaultRedirect
	}

	if parsedURL.IsAbs() {
		// Check for allowed host and scheme (http/https) to prevent XSS
		if (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || !cfg.IsAllowedHost(parsedURL.Hostname()) {
			slog.Warn("Unsafe absolute redirect attempted", "host", parsedURL.Hostname(), "scheme", parsedURL.Scheme, "user", username)
			return defaultRedirect
		}
		return rd
	}

	// Relative URL - ensure it starts with / and not // (checked above)
	if !strings.HasPrefix(rd, "/") {
		return "/" + rd
	}

	return rd
}

type ParsedUA struct {
	OS       string
	Browser  string
	Platform string
	IsMobile bool
}

func ParseUserAgent(ua string) ParsedUA {
	os := "Unknown OS"
	platform := ""
	isMobile := false

	if strings.Contains(ua, "Android") {
		os = "Android"
		isMobile = true
	} else if strings.Contains(ua, "iPhone") {
		os = "iOS"
		isMobile = true
		platform = "iPhone"
	} else if strings.Contains(ua, "iPad") {
		os = "iOS"
		isMobile = true
		platform = "iPad"
	} else if strings.Contains(ua, "Windows") {
		os = "Windows"
		platform = "PC"
	} else if strings.Contains(ua, "Macintosh") {
		os = "macOS"
		platform = "Mac"
	} else if strings.Contains(ua, "Linux") {
		os = "Linux"
		platform = "PC"
	}

	browser := "Unknown Browser"
	if strings.Contains(ua, "Opera/") || strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera") {
		browser = "Opera"
	} else if strings.Contains(ua, "Edg/") {
		browser = "Edge"
	} else if strings.Contains(ua, "CriOS/") {
		browser = "Chrome"
	} else if strings.Contains(ua, "FxiOS/") {
		browser = "Firefox"
	} else if strings.Contains(ua, "Chrome/") {
		browser = "Chrome"
	} else if strings.Contains(ua, "Firefox/") {
		browser = "Firefox"
	} else if strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "CriOS/") && !strings.Contains(ua, "FxiOS/") {
		browser = "Safari"
	}

	return ParsedUA{OS: os, Browser: browser, Platform: platform, IsMobile: isMobile}
}

func IsUserAgentCompatible(oldUA, newUA string) bool {
	if oldUA == newUA {
		return true
	}
	if oldUA == "" || newUA == "" {
		return false
	}

	oldParsed := ParseUserAgent(oldUA)
	newParsed := ParseUserAgent(newUA)

	// Fallback to strict string matching if browser or OS cannot be reliably parsed/identified
	if oldParsed.Browser == "Unknown Browser" || oldParsed.OS == "Unknown OS" ||
		newParsed.Browser == "Unknown Browser" || newParsed.OS == "Unknown OS" {
		return oldUA == newUA
	}

	if oldParsed.Browser != newParsed.Browser {
		return false
	}

	// Treat Linux and Android as compatible platforms (tablet desktop/mobile toggles)
	isOldLinuxOrAndroid := (oldParsed.OS == "Linux" || oldParsed.OS == "Android")
	isNewLinuxOrAndroid := (newParsed.OS == "Linux" || newParsed.OS == "Android")
	if isOldLinuxOrAndroid && isNewLinuxOrAndroid {
		return true
	}

	return oldParsed.OS == newParsed.OS
}

func ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return fmt.Errorf("username must be between 3 and 32 characters long")
	}
	// Alphanumeric, underscores, hyphens, and dots
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username can only contain alphanumeric characters, dots, underscores, and hyphens")
	}
	return nil
}
