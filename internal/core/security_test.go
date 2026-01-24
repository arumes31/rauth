package core

import (
	"testing"
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
		MinPasswordLength:     8,
		RequirePasswordUpper:  true,
		RequirePasswordLower:  true,
		RequirePasswordNumber: true,
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
