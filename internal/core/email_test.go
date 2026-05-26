package core

import (
	"net/smtp"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendEmail_NotConfigured(t *testing.T) {
	os.Setenv("SMTP_HOST", "")
	defer os.Unsetenv("SMTP_HOST")

	err := SendEmail("test@example.com", "Test Subject", "Test Body")
	assert.NoError(t, err)
}

func TestSend2FAModifiedNotification(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_FROM")

	var sentTo []string
	var sentMsg string

	oldSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		sentTo = to
		sentMsg = string(msg)
		return nil
	}
	defer func() { sendMail = oldSendMail }()

	Send2FAModifiedNotification("user@example.com", "testuser", "enabled", "127.0.0.1")

	assert.Equal(t, []string{"user@example.com"}, sentTo)
	assert.Contains(t, sentMsg, "Subject: [RAuth] Security Alert: 2FA enabled")
	assert.Contains(t, sentMsg, "Two-Factor Authentication enabled")
	assert.Contains(t, sentMsg, "testuser")
	assert.Contains(t, sentMsg, "127.0.0.1")
}

func TestSendLoginNotification(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_FROM")

	var sentTo []string
	var sentMsg string

	oldSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		sentTo = to
		sentMsg = string(msg)
		return nil
	}
	defer func() { sendMail = oldSendMail }()

	SendLoginNotification("user@example.com", "testuser", "192.168.1.1", "US")

	assert.Equal(t, []string{"user@example.com"}, sentTo)
	assert.Contains(t, sentMsg, "Subject: [RAuth] Security Alert: New Login Detected")
	assert.Contains(t, sentMsg, "New Login Detected")
	assert.Contains(t, sentMsg, "testuser")
	assert.Contains(t, sentMsg, "192.168.1.1")
	assert.Contains(t, sentMsg, "US")
}

func TestSendPasswordChangeNotification(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_FROM")

	var sentTo []string
	var sentMsg string

	oldSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		sentTo = to
		sentMsg = string(msg)
		return nil
	}
	defer func() { sendMail = oldSendMail }()

	SendPasswordChangeNotification("user@example.com", "testuser", "10.0.0.1")

	assert.Equal(t, []string{"user@example.com"}, sentTo)
	assert.Contains(t, sentMsg, "Subject: [RAuth] Security Alert: Password Changed")
	assert.Contains(t, sentMsg, "Password Changed")
	assert.Contains(t, sentMsg, "testuser")
	assert.Contains(t, sentMsg, "10.0.0.1")
}

func TestSendAccountCreatedNotification(t *testing.T) {
	os.Setenv("SMTP_HOST", "localhost")
	os.Setenv("SMTP_FROM", "rauth@example.com")
	defer os.Unsetenv("SMTP_HOST")
	defer os.Unsetenv("SMTP_FROM")

	var sentTo []string
	var sentMsg string

	oldSendMail := sendMail
	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		sentTo = to
		sentMsg = string(msg)
		return nil
	}
	defer func() { sendMail = oldSendMail }()

	SendAccountCreatedNotification("user@example.com", "newuser")

	assert.Equal(t, []string{"user@example.com"}, sentTo)
	assert.Contains(t, sentMsg, "Subject: [RAuth] Welcome: Your Account is Ready")
	assert.Contains(t, sentMsg, "Welcome to RAuth")
	assert.Contains(t, sentMsg, "newuser")
}
