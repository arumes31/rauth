package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	key := "12345678901234567890123456789012" // 32 bytes
	plaintext := "secret token message"

	encrypted, err := EncryptToken(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptToken(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text mismatch. Got %s, want %s", decrypted, plaintext)
	}
}

func TestDecryptTokenErrors(t *testing.T) {
	key := "12345678901234567890123456789012"

	t.Run("Invalid base64", func(t *testing.T) {
		_, err := DecryptToken("not-base64-!", key)
		assert.Error(t, err)
	})

	t.Run("Wrong key size", func(t *testing.T) {
		_, err := DecryptToken("some-data", "too-short")
		assert.Error(t, err)
	})

	t.Run("Invalid ciphertext", func(t *testing.T) {
		// Valid base64 but not a valid encrypted block
		_, err := DecryptToken("YmFkLWRhdGE=", key)
		assert.Error(t, err)
	})
}

func TestEncryptionLargeInput(t *testing.T) {
	key := "12345678901234567890123456789012"
	largeInput := make([]byte, 1024*1024) // 1MB
	for i := range largeInput {
		largeInput[i] = 'A'
	}

	encrypted, err := EncryptToken(string(largeInput), key)
	assert.NoError(t, err)

	decrypted, err := DecryptToken(encrypted, key)
	assert.NoError(t, err)
	assert.Equal(t, string(largeInput), decrypted)
}

func TestValidatePasswordComplexity(t *testing.T) {
	cfg := &Config{
		MinPasswordLength:      8,
		RequirePasswordUpper:   true,
		RequirePasswordLower:   true,
		RequirePasswordNumber:  true,
		RequirePasswordSpecial: true,
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"Valid password", "Pass1234!", false},
		{"Too short", "Pas1!", true},
		{"Missing upper", "pass1234!", true},
		{"Missing lower", "PASS1234!", true},
		{"Missing number", "Password!", true},
		{"Missing special", "Pass12345", true},
		{"Only special and numbers", "!@#$%1234", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "mypassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Hashing failed: %v", err)
	}

	if !CheckPasswordHash(password, hash) {
		t.Error("Password check failed for correct password")
	}

	if CheckPasswordHash("wrongpassword", hash) {
		t.Error("Password check succeeded for wrong password")
	}
}

func TestValidatePasswordDetails(t *testing.T) {
	cfg := &Config{
		MinPasswordLength:      8,
		RequirePasswordUpper:   true,
		RequirePasswordLower:   true,
		RequirePasswordNumber:  true,
		RequirePasswordSpecial: true,
	}

	tests := []struct {
		password string
		valid    bool
	}{
		{"Valid123!", true},
		{"short1!", false},
		{"noupper123!", false},
		{"NOLOWER123!", false},
		{"NoNumber!", false},
		{"NoSpecial123", false},
	}

	for _, tt := range tests {
		err := ValidatePassword(tt.password, cfg)
		if tt.valid && err != nil {
			t.Errorf("Password %s should be valid but got error: %v", tt.password, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("Password %s should be invalid but got no error", tt.password)
		}
	}
}

// Fuzzing

func FuzzValidatePassword(f *testing.F) {
	cfg := &Config{
		MinPasswordLength:      8,
		RequirePasswordUpper:   true,
		RequirePasswordLower:   true,
		RequirePasswordNumber:  true,
		RequirePasswordSpecial: true,
	}
	f.Add("Password123!")
	f.Add("short")
	f.Add("NONUMBER!")
	f.Fuzz(func(t *testing.T, password string) {
		_ = ValidatePassword(password, cfg)
	})
}

func FuzzDecryptToken(f *testing.F) {
	key := "32byte-secret-key-for-testing-!!"
	f.Add("some-random-invalid-base64")
	f.Add("dmFsaWQ=") // valid base64 but not encrypted
	f.Fuzz(func(t *testing.T, encryptedText string) {
		_, _ = DecryptToken(encryptedText, key)
	})
}

// Benchmarks

func BenchmarkHashPassword(b *testing.B) {
	password := "securepassword123"
	for i := 0; i < b.N; i++ {
		_, _ = HashPassword(password)
	}
}

func BenchmarkCheckPasswordHash(b *testing.B) {
	password := "securepassword123"
	hash, _ := HashPassword(password)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckPasswordHash(password, hash)
	}
}

func BenchmarkEncryptToken(b *testing.B) {
	key := "32byte-secret-key-for-testing-!!"
	text := "standard-session-token-string"
	for i := 0; i < b.N; i++ {
		_, _ = EncryptToken(text, key)
	}
}

func BenchmarkDecryptToken(b *testing.B) {
	key := "32byte-secret-key-for-testing-!!"
	text := "standard-session-token-string"
	encrypted, _ := EncryptToken(text, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptToken(encrypted, key)
	}
}

func TestValidateRedirectURL(t *testing.T) {
	cfg := &Config{AllowedHosts: []string{"example.com"}}

	tests := []struct {
		name     string
		rd       string
		expected string
	}{
		{"Empty string", "", "/default"},
		{"Valid relative path", "/dashboard", "/dashboard"},
		{"Valid absolute URL", "https://example.com/page", "https://example.com/page"},
		{"Protocol relative double slash", "//evil.com", "/default"},
		{"Protocol relative slash backslash", "/\\evil.com", "/default"},
		{"Protocol relative double backslash", "\\\\evil.com", "/default"},
		{"Protocol relative backslash slash", "\\/evil.com", "/default"},
		{"Protocol relative single backslash", "\\evil.com", "/default"},
		{"Leading space double slash", "  //evil.com", "/default"},
		{"Leading space relative path", "  /dashboard  ", "/dashboard"},
		{"Missing leading slash", "dashboard", "/dashboard"},
		{"Invalid scheme XSS", "javascript:alert(1)", "/default"},
		{"Unallowed host", "https://evil.com/page", "/default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRedirectURL(tt.rd, "/default", "testuser", cfg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsUserAgentCompatible(t *testing.T) {
	tests := []struct {
		name     string
		oldUA    string
		newUA    string
		expected bool
	}{
		{
			name:     "Exactly identical UAs",
			oldUA:    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			expected: true,
		},
		{
			name:     "Android to Linux Chrome (Tablet Desktop Mode Toggle)",
			oldUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			expected: true,
		},
		{
			name:     "Android to Linux Firefox (Tablet Desktop Mode Toggle)",
			oldUA:    "Mozilla/5.0 (Android; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0",
			newUA:    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
			expected: true,
		},
		{
			name:     "Chrome vs Firefox on same OS",
			oldUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
			expected: false,
		},
		{
			name:     "Chrome Linux to Chrome Windows (Different OS)",
			oldUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			expected: false,
		},
		{
			name:     "Chrome Android to Chrome macOS (Different OS)",
			oldUA:    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			expected: false,
		},
		{
			name:     "Empty strings",
			oldUA:    "",
			newUA:    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
			expected: false,
		},
		{
			name:     "Different Unknown UAs (Strict Fallback)",
			oldUA:    "Mozilla/5.0 (Original Browser)",
			newUA:    "Mozilla/5.0 (Attacker Browser)",
			expected: false,
		},
		{
			name:     "Identical Unknown UAs (Strict Fallback)",
			oldUA:    "Mozilla/5.0 (Original Browser)",
			newUA:    "Mozilla/5.0 (Original Browser)",
			expected: true,
		},
		{
			name:     "Opera Linux to Opera Android (Compatible Platforms)",
			oldUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
			newUA:    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 OPR/106.0.0.0",
			expected: true,
		},
		{
			name:     "Opera vs Chrome (Incompatible Brands)",
			oldUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
			newUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expected: false,
		},
		{
			name:     "CriOS (Chrome iOS) vs Chrome Android (Different OS)",
			oldUA:    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/95.0.4638.50 Mobile/15E148 Safari/604.1",
			newUA:    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.50 Mobile Safari/537.36",
			expected: false,
		},
		{
			name:     "FxiOS (Firefox iOS) vs Firefox Android (Different OS)",
			oldUA:    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/40.0 Mobile/15E148 Safari/605.1.15",
			newUA:    "Mozilla/5.0 (Android; Mobile; rv:40.0) Gecko/40.0 Firefox/40.0",
			expected: false,
		},
		{
			name:     "CriOS vs FxiOS on iOS (Different Brands)",
			oldUA:    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/95.0.4638.50 Mobile/15E148 Safari/604.1",
			newUA:    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/40.0 Mobile/15E148 Safari/605.1.15",
			expected: false,
		},
		{
			name:     "CriOS vs Safari on iOS (Different Brands)",
			oldUA:    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/95.0.4638.50 Mobile/15E148 Safari/604.1",
			newUA:    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := IsUserAgentCompatible(tt.oldUA, tt.newUA)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestLegacyDecryption(t *testing.T) {
	key := "test-secret-key"
	plaintext := "secret-message"

	// Encrypt using legacy method manually to simulate old data
	block, err := aes.NewCipher(getAESKeyLegacy(key))
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("Failed to read nonce: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encrypted := base64.StdEncoding.EncodeToString(ciphertext)

	// Decrypt using the updated DecryptToken
	decrypted, err := DecryptToken(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt legacy data: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Expected %s, got %s", plaintext, decrypted)
	}

	// Also verify that NEW encryption can be decrypted
	newEncrypted, err := EncryptToken(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt with new method: %v", err)
	}
	newDecrypted, err := DecryptToken(newEncrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt new data: %v", err)
	}
	if newDecrypted != plaintext {
		t.Errorf("Expected %s, got %s", plaintext, newDecrypted)
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"Valid Email", "test@example.com", false},
		{"Valid Email With Plus", "test+123@example.com", false},
		{"Valid email with dots", "test.name@example.com", false},
		{"Empty email", "", true},
		{"Invalid Email - No At", "testexample.com", true},
		{"Invalid Email - No Domain", "test@", true},
		{"Missing TLD", "test@example", true},
		{"Invalid characters", "test!@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"Length 10", 10},
		{"Length 32", 32},
		{"Length 64", 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateRandomString(tt.length)
			require.NotEmpty(t, got)
			got2 := GenerateRandomString(tt.length)
			require.NotEqual(t, got, got2)
		})
	}
}

func TestDecrypt2FASecret(t *testing.T) {
	key := "12345678901234567890123456789012"
	plainSecret := "my-plain-secret"
	encryptedSecret, err := EncryptToken(plainSecret, key)
	require.NoError(t, err)
	encSecret := "enc:" + encryptedSecret

	tests := []struct {
		name   string
		secret string
		key    string
		want   string
	}{
		{"Empty Secret", "", key, ""},
		{"Plain Secret", "plain_secret", key, "plain_secret"},
		{"Valid Encrypted Secret", encSecret, key, plainSecret},
		{"Invalid Encrypted Secret", "enc:invalid_data", key, "enc:invalid_data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decrypt2FASecret(tt.secret, tt.key)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFormatUserAgent(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"Empty", "", "Unknown Device"},
		{"Chrome on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", "Chrome on Windows"},
		{"Firefox on macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0", "Firefox on macOS"},
		{"Safari on iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1", "Safari on iOS"},
		{"Chrome on Android", "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36", "Chrome on Android"},
		{"Opera on Linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 OPR/77.0.4054.172", "Opera on Linux"},
		{"Edge on Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59", "Edge on Windows"},
		{"CriOS on iPad", "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.80 Mobile/15E148 Safari/604.1", "Chrome on iOS"},
		{"FxiOS on iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/34.0 Mobile/15E148 Safari/605.1.15", "Firefox on iOS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatUserAgent(tt.ua)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetDeviceIcon(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"Android", "Mozilla/5.0 (Linux; Android 11)", "bi-android2"},
		{"iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6)", "bi-apple"},
		{"iPad", "Mozilla/5.0 (iPad; CPU OS 14_6)", "bi-apple"},
		{"Windows", "Mozilla/5.0 (Windows NT 10.0)", "bi-microsoft"},
		{"Macintosh", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15)", "bi-apple"},
		{"Linux", "Mozilla/5.0 (X11; Linux x86_64)", "bi-ubuntu"},
		{"Unknown", "Unknown UA", "bi-display"},
		{"Android direct", "Android", "bi-android2"},
		{"iPhone direct", "iPhone", "bi-apple"},
		{"iPad direct", "iPad", "bi-apple"},
		{"Windows direct", "Windows", "bi-microsoft"},
		{"Macintosh direct", "Macintosh", "bi-apple"},
		{"Linux direct", "Linux", "bi-ubuntu"},
		{"Unknown direct", "Unknown", "bi-display"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetDeviceIcon(tt.ua)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		wantErr bool
	}{
		{"Valid User", "test_user.123-abc", false},
		{"Valid username short", "testuser", false},
		{"Valid with dot", "test.user", false},
		{"Valid with hyphen", "test-user", false},
		{"Valid with underscore", "test_user", false},
		{"Too Short", "ab", true},
		{"Too Long", "thisusernameiswaytoolongtobevalid33", true},
		{"Too long 2", "thisusernameiswaytoolongtobeconsideredvalid", true},
		{"Invalid Characters", "user@name!", true},
		{"Invalid characters 2", "test user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.user)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
