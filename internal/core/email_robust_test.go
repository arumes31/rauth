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
