package core

import (
	"errors"
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendLoginNotificationRobust(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_FROM", "noreply@rauth.example.com")
	t.Setenv("PUBLIC_URL", "https://auth.example.com")

	origSendMail := sendMail
	defer func() { sendMail = origSendMail }()

	var capturedAddr string
	var capturedFrom string
	var capturedTo []string
	var capturedMsg string
	var mockErr error

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedAddr = addr
		capturedFrom = from
		capturedTo = to
		capturedMsg = string(msg)
		return mockErr
	}

	tests := []struct {
		name     string
		email    string
		username string
		ip       string
		country  string
		mockErr  error
		wantErr  bool
	}{
		{
			name:     "Success Path",
			email:    "user@example.com",
			username: "testuser",
			ip:       "192.168.1.1",
			country:  "United States",
			mockErr:  nil,
			wantErr:  false,
		},
		{
			name:     "HTML Injection in Username",
			email:    "user@example.com",
			username: "<script>alert('xss')</script>",
			ip:       "10.0.0.1",
			country:  "Local",
			mockErr:  nil,
			wantErr:  false,
		},
		{
			name:     "HTML Injection in Country",
			email:    "user@example.com",
			username: "safeuser",
			ip:       "8.8.8.8",
			country:  "<b>Evil</b>",
			mockErr:  nil,
			wantErr:  false,
		},
		{
			name:     "SMTP Error Handling",
			email:    "user@example.com",
			username: "testuser",
			ip:       "1.1.1.1",
			country:  "Cloudflare",
			mockErr:  errors.New("SMTP connection failed"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockErr = tt.mockErr

			// Reset captures
			capturedAddr = ""
			capturedFrom = ""
			capturedTo = nil
			capturedMsg = ""

			SendLoginNotification(tt.email, tt.username, tt.ip, tt.country)

			// Verify SendEmail was called with expected basic params
			assert.Equal(t, "smtp.example.com:587", capturedAddr)
			assert.Equal(t, "noreply@rauth.example.com", capturedFrom)
			assert.Equal(t, []string{tt.email}, capturedTo)

			// Verify Subject
			assert.Contains(t, capturedMsg, "Subject: [RAuth] Security Alert: New Login Detected")

			// Verify Content and Escaping
			if tt.name == "HTML Injection in Username" {
				assert.Contains(t, capturedMsg, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;")
				assert.NotContains(t, capturedMsg, "<script>")
			} else if tt.name == "HTML Injection in Country" {
				assert.Contains(t, capturedMsg, "&lt;b&gt;Evil&lt;/b&gt;")
				assert.NotContains(t, capturedMsg, "<b>")
			} else if tt.name == "Success Path" {
				assert.Contains(t, capturedMsg, "testuser")
				assert.Contains(t, capturedMsg, "192.168.1.1")
				assert.Contains(t, capturedMsg, "United States")
			}

			// Verify Public URL and Logo
			assert.Contains(t, capturedMsg, "https://auth.example.com/rauthprofile")
			assert.Contains(t, capturedMsg, "https://auth.example.com/static/favicon.png")
		})
	}
}

func TestSendEmail_DirectError(t *testing.T) {
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_FROM", "test@test.com")

	origSendMail := sendMail
	defer func() { sendMail = origSendMail }()

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		return errors.New("direct failure")
	}

	err := SendEmail("to@to.com", "Sub", "Body")
	assert.Error(t, err)
	assert.Equal(t, "direct failure", err.Error())
}
