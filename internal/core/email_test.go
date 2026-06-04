package core

import (
	"bytes"
	"errors"
	"log/slog"
	"net/smtp"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendEmail_NotConfigured(t *testing.T) {
	// Setup log capturing
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	// We don't want to actually send an email in tests anyway unless mocked
	t.Setenv("SMTP_HOST", "")

	err := SendEmail("test@example.com", "Test Subject", "Test Body")
	assert.NoError(t, err) // Should return nil when not configured

	logOutput := buf.String()
	assert.Contains(t, logOutput, "SMTP not configured, skipping email")
	assert.Contains(t, logOutput, "test@example.com")
	assert.Contains(t, logOutput, "Test Subject")
}

func TestSendEmail_SMTPError(t *testing.T) {
	// Setup log capturing
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	// Setup config
	t.Setenv("SMTP_HOST", "localhost")

	// Mock sendMail to return error
	smtpErr := errors.New("smtp connection failed")
	origSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		return smtpErr
	}
	defer func() { sendMail = origSendMail }()

	err := SendEmail("test@example.com", "Subject", "Body")
	assert.Error(t, err)
	assert.Equal(t, smtpErr, err)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "Failed to send email")
	assert.Contains(t, logOutput, "smtp connection failed")
	assert.Contains(t, logOutput, "test@example.com")
}

func TestNotifications(t *testing.T) {
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_FROM", "rauth@example.com")
	t.Setenv("PUBLIC_URL", "https://rauth.example.com")

	var capturedFrom string
	var capturedTo []string
	var capturedMsg string

	origSendMail := sendMail
	defer func() { sendMail = origSendMail }()

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedFrom = from
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}

	t.Run("SendLoginNotification", func(t *testing.T) {
		SendLoginNotification("user@example.com", "testuser<script>", "1.2.3.4", "TestCountry", "Chrome on Windows (PC)")

		assert.Equal(t, "rauth@example.com", capturedFrom)
		assert.Equal(t, []string{"user@example.com"}, capturedTo)
		assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: New Login Detected")
		assert.Contains(t, capturedMsg, "testuser&lt;script&gt;")
		assert.Contains(t, capturedMsg, "Chrome on Windows (PC)")
		assert.Contains(t, capturedMsg, "1.2.3.4")
		assert.Contains(t, capturedMsg, "TestCountry")
		assert.Contains(t, capturedMsg, "https://rauth.example.com/rauthprofile")
	})

	t.Run("SendPasswordChangeNotification", func(t *testing.T) {
		SendPasswordChangeNotification("user@example.com", "testuser", "5.6.7.8", "Chrome on Windows (PC)")

		assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: Password Changed")
		assert.Contains(t, capturedMsg, "testuser")
		assert.Contains(t, capturedMsg, "Chrome on Windows (PC)")
		assert.Contains(t, capturedMsg, "5.6.7.8")
	})

	t.Run("SendAccountCreatedNotification", func(t *testing.T) {
		SendAccountCreatedNotification("user@example.com", "newuser")

		assert.Contains(t, capturedMsg, "Subject: [RAuth] Welcome: Your Account is Ready")
		assert.Contains(t, capturedMsg, "newuser")
		assert.Contains(t, capturedMsg, "https://rauth.example.com/rauthlogin")
	})

	t.Run("Send2FAModifiedNotification", func(t *testing.T) {
		Send2FAModifiedNotification("user@example.com", "testuser", "Enabled", "9.10.11.12", "Firefox on Android [Mobile]")

		assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: 2FA Enabled")
		assert.Contains(t, capturedMsg, "testuser")
		assert.Contains(t, capturedMsg, "Enabled")
		assert.Contains(t, capturedMsg, "Firefox on Android [Mobile]")
		assert.Contains(t, capturedMsg, "9.10.11.12")
	})
}

func TestSendEmail_HTMLWrap(t *testing.T) {
	err := os.Setenv("SMTP_HOST", "localhost")
	require.NoError(t, err)
	defer func() {
		err := os.Unsetenv("SMTP_HOST")
		require.NoError(t, err)
	}()

	var capturedMsg string
	oldSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedMsg = string(msg)
		return nil
	}
	defer func() { sendMail = oldSendMail }()

	err = SendEmail("test@example.com", "Plain Subject", "This is plain text")
	assert.NoError(t, err)
	assert.Contains(t, capturedMsg, "<html>")
	assert.Contains(t, capturedMsg, "This is plain text")

	err = SendEmail("test@example.com", "HTML Subject", "<html><body>HTML content</body></html>")
	assert.NoError(t, err)
	assert.True(t, strings.Count(capturedMsg, "<html>") == 1)
}

func TestSendAccountCreatedNotificationRobust(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "noreply@rauth.example.com")
	t.Setenv("PUBLIC_URL", "https://auth.example.com")

	var capturedFrom string
	var capturedTo []string
	var capturedMsg string

	origSendMail := sendMail
	defer func() { sendMail = origSendMail }()

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedFrom = from
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}

	testEmail := "newuser@example.com"
	testUsername := "newuser<script>alert(1)</script>"

	SendAccountCreatedNotification(testEmail, testUsername)

	assert.Equal(t, "noreply@rauth.example.com", capturedFrom)
	assert.Equal(t, []string{testEmail}, capturedTo)
	assert.Contains(t, capturedMsg, "Subject: [RAuth] Welcome: Your Account is Ready")

	// Verify HTML escaping
	assert.Contains(t, capturedMsg, "newuser&lt;script&gt;alert(1)&lt;/script&gt;")
	assert.NotContains(t, capturedMsg, "<script>")

	// Verify Public URL usage
	assert.Contains(t, capturedMsg, "https://auth.example.com/rauthlogin")

	// Verify logo URL replacement
	assert.Contains(t, capturedMsg, "https://auth.example.com/static/favicon.png")

	// Verify it's wrapped in the template
	assert.Contains(t, capturedMsg, "<!DOCTYPE html>")
	assert.Contains(t, capturedMsg, "RAuth Security</h1>")
}
