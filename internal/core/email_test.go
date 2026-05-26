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
	// We don't want to actually send an email in tests anyway unless mocked
	os.Setenv("SMTP_HOST", "")
	defer os.Unsetenv("SMTP_HOST")

	err := SendEmail("test@example.com", "Test Subject", "Test Body")
	assert.NoError(t, err) // Should return nil when not configured
}

func TestSendPasswordChangeNotification(t *testing.T) {
	// Setup SMTP config
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_PORT")
	defer os.Unsetenv("SMTP_FROM")

	var capturedAddr string
	var capturedFrom string
	var capturedTo []string
	var capturedMsg string

	// Mock smtpSendMail
	oldSendMail := smtpSendMail
	smtpSendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedAddr = addr
		capturedFrom = from
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}
	defer func() { smtpSendMail = oldSendMail }()

	email := "user@example.com"
	username := "testuser"
	ip := "192.168.1.1"

	SendPasswordChangeNotification(email, username, ip)

	assert.Equal(t, "localhost:587", capturedAddr)
	assert.Equal(t, "rauth@example.com", capturedFrom)
	assert.Equal(t, []string{email}, capturedTo)
	assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: Password Changed")
	assert.Contains(t, capturedMsg, "testuser")
	assert.Contains(t, capturedMsg, ip)
	assert.Contains(t, capturedMsg, "Password Changed")
}

func TestSendLoginNotification(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_PORT")
	defer os.Unsetenv("SMTP_FROM")

	var capturedTo []string
	var capturedMsg string

	oldSendMail := smtpSendMail
	smtpSendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}
	defer func() { smtpSendMail = oldSendMail }()

	email := "user@example.com"
	username := "testuser"
	ip := "1.2.3.4"
	country := "Switzerland"

	SendLoginNotification(email, username, ip, country)

	assert.Equal(t, []string{email}, capturedTo)
	assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: New Login Detected")
	assert.Contains(t, capturedMsg, username)
	assert.Contains(t, capturedMsg, ip)
	assert.Contains(t, capturedMsg, country)
}

func TestSendAccountCreatedNotification(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_PORT")
	defer os.Unsetenv("SMTP_FROM")

	var capturedTo []string
	var capturedMsg string

	oldSendMail := smtpSendMail
	smtpSendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}
	defer func() { smtpSendMail = oldSendMail }()

	email := "newuser@example.com"
	username := "newuser"

	SendAccountCreatedNotification(email, username)

	assert.Equal(t, []string{email}, capturedTo)
	assert.Contains(t, capturedMsg, "Subject: [RAuth] Welcome: Your Account is Ready")
	assert.Contains(t, capturedMsg, username)
	assert.Contains(t, capturedMsg, "An administrator has created an account for you")
}

func TestSend2FAModifiedNotification(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_PORT")
	defer os.Unsetenv("SMTP_FROM")

	var capturedTo []string
	var capturedMsg string

	oldSendMail := smtpSendMail
	smtpSendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}
	defer func() { smtpSendMail = oldSendMail }()

	email := "user@example.com"
	username := "testuser"
	action := "ENABLED"
	ip := "5.6.7.8"

	Send2FAModifiedNotification(email, username, action, ip)

	assert.Equal(t, []string{email}, capturedTo)
	assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: 2FA ENABLED")
	assert.Contains(t, capturedMsg, username)
	assert.Contains(t, capturedMsg, action)
	assert.Contains(t, capturedMsg, ip)
}

func TestSendEmail_HTMLWrap(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	defer os.Unsetenv("SMTP_HOST")

	var capturedMsg string
	oldSendMail := smtpSendMail
	smtpSendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedMsg = string(msg)
		return nil
	}
	defer func() { smtpSendMail = oldSendMail }()

	err := SendEmail("test@example.com", "Plain Subject", "This is plain text")
	assert.NoError(t, err)
	assert.Contains(t, capturedMsg, "<html>")
	assert.Contains(t, capturedMsg, "This is plain text")

	err = SendEmail("test@example.com", "HTML Subject", "<html><body>HTML content</body></html>")
	assert.NoError(t, err)
	// Should NOT wrap if it already has <html>
	// Actually, the logic is: if !strings.Contains(body, "<html>") { wrap }
	// So it should contain it exactly once (from the input)
	assert.True(t, strings.Count(capturedMsg, "<html>") == 1)
}
