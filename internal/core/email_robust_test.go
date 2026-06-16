package core

import (
	"bytes"
	"errors"
	"log/slog"
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendEmail_NoSMTPHost_LogsWarning(t *testing.T) {
	// Setup log capturing
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	// Ensure SMTP_HOST is empty
	t.Setenv("SMTP_HOST", "")

	err := SendEmail("test@example.com", "Subject", "Body")
	assert.NoError(t, err)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "SMTP not configured, skipping email")
	assert.Contains(t, logOutput, "test@example.com")
	assert.Contains(t, logOutput, "Subject")
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

func TestSendPasswordChangeNotificationRobust(t *testing.T) {
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

	testEmail := "user@example.com"
	testUsername := "user<script>alert(1)</script>"
	testIP := "192.168.1.1<script>"
	testDevice := "Safari on Mac <script>"

	SendPasswordChangeNotification(testEmail, testUsername, testIP, testDevice)

	assert.Equal(t, "noreply@rauth.example.com", capturedFrom)
	assert.Equal(t, []string{testEmail}, capturedTo)
	assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: Password Changed")

	// Verify HTML escaping
	assert.Contains(t, capturedMsg, "user&lt;script&gt;alert(1)&lt;/script&gt;")
	assert.NotContains(t, capturedMsg, "<script>")

	assert.Contains(t, capturedMsg, "192.168.1.1&lt;script&gt;")
	assert.Contains(t, capturedMsg, "Safari on Mac &lt;script&gt;")

	// Verify it's wrapped in the template
	assert.Contains(t, capturedMsg, "<!DOCTYPE html>")
	assert.Contains(t, capturedMsg, "RAuth Security</h1>")
}
