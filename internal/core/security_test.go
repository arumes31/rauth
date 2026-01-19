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
