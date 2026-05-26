package core

import (
	"net/smtp"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendEmail_NotConfigured(t *testing.T) {
	// Ensure SMTP is not configured
	_ = os.Unsetenv("SMTP_HOST")
	err := SendEmail("test@example.com", "Test Subject", "Test Body")
	assert.NoError(t, err) // Should return nil when not configured
}

func TestNotifications(t *testing.T) {
	// Mock SMTP host
	_ = os.Setenv("SMTP_HOST", "localhost")
	_ = os.Setenv("PUBLIC_URL", "http://rauth.test")
	defer func() {
		_ = os.Unsetenv("SMTP_HOST")
		_ = os.Unsetenv("PUBLIC_URL")
	}()

	var capturedTo []string
	var capturedSubject string
	var capturedBody string

	// Mock sendMail
	originalSendMail := sendMail
	defer func() { sendMail = originalSendMail }()

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedTo = to
		// Extract subject and body from msg
		sMsg := string(msg)
		lines := strings.Split(sMsg, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Subject: ") {
				capturedSubject = strings.TrimPrefix(line, "Subject: ")
			}
		}
		// Body is everything after the first \r\n\r\n
		parts := strings.SplitN(sMsg, "\r\n\r\n", 2)
		if len(parts) > 1 {
			capturedBody = parts[1]
		}
		return nil
	}

	t.Run("SendAccountCreatedNotification", func(t *testing.T) {
		testEmail := "user1@example.com"
		testUser := "testuser1"
		SendAccountCreatedNotification(testEmail, testUser)
		assert.Equal(t, []string{testEmail}, capturedTo)
		assert.Equal(t, "[RAuth] Welcome: Your Account is Ready", capturedSubject)
		assert.Contains(t, capturedBody, testUser)
		assert.Contains(t, capturedBody, "Welcome to RAuth")
	})

	t.Run("SendLoginNotification", func(t *testing.T) {
		testEmail := "user2@example.com"
		testUser := "testuser2"
		SendLoginNotification(testEmail, testUser, "1.2.3.4", "TestCountry")
		assert.Equal(t, []string{testEmail}, capturedTo)
		assert.Equal(t, "[RAuth] Security Alert: New Login Detected", capturedSubject)
		assert.Contains(t, capturedBody, testUser)
		assert.Contains(t, capturedBody, "1.2.3.4")
		assert.Contains(t, capturedBody, "TestCountry")
	})

	t.Run("SendPasswordChangeNotification", func(t *testing.T) {
		testEmail := "user3@example.com"
		testUser := "testuser3"
		SendPasswordChangeNotification(testEmail, testUser, "5.6.7.8")
		assert.Equal(t, []string{testEmail}, capturedTo)
		assert.Equal(t, "[RAuth] Security Alert: Password Changed", capturedSubject)
		assert.Contains(t, capturedBody, testUser)
		assert.Contains(t, capturedBody, "5.6.7.8")
	})

	t.Run("Send2FAModifiedNotification", func(t *testing.T) {
		testEmail := "user4@example.com"
		testUser := "testuser4"
		Send2FAModifiedNotification(testEmail, testUser, "Enabled", "9.10.11.12")
		assert.Equal(t, []string{testEmail}, capturedTo)
		assert.Equal(t, "[RAuth] Security Alert: 2FA Enabled", capturedSubject)
		assert.Contains(t, capturedBody, testUser)
		assert.Contains(t, capturedBody, "Enabled")
		assert.Contains(t, capturedBody, "9.10.11.12")
	})
}
