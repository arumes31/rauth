package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func ValidatePassword(password string, cfg *Config) error {
	if len(password) < cfg.MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", cfg.MinPasswordLength)
	}
	var (
		hasUpper   = regexp.MustCompile(`[A-Z]`).MatchString
		hasLower   = regexp.MustCompile(`[a-z]`).MatchString
		hasNumber  = regexp.MustCompile(`[0-9]`).MatchString
		hasSpecial = regexp.MustCompile(`[!@#\$%\^&\*]`).MatchString
	)
	if cfg.RequirePasswordUpper && !hasUpper(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if cfg.RequirePasswordLower && !hasLower(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if cfg.RequirePasswordNumber && !hasNumber(password) {
		return fmt.Errorf("password must contain at least one number")
	}
	if cfg.RequirePasswordSpecial && !hasSpecial(password) {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getAESKey(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
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

	block, err := aes.NewCipher(getAESKey(key))
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
	if secret == "" { return "" }
	encrypted, err := EncryptToken(secret, key)
	if err != nil { return secret } // Fallback to plain if encryption fails (should not happen)
	return "enc:" + encrypted
}

func Decrypt2FASecret(secret string, key string) string {
	if secret == "" { return "" }
	if !strings.HasPrefix(secret, "enc:") {
		return secret // Already plain
	}
	decrypted, err := DecryptToken(secret[4:], key)
	if err != nil {
		return secret // Fallback to plain/as-is if decryption fails
	}
	return decrypted
}
