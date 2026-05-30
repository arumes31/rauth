package core

import (
	"net/smtp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendAccountCreatedNotification_Table(t *testing.T) {
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

	tests := []struct {
		name         string
		email        string
		username     string
		wantTo       []string
		wantInMsg    []string
		notInMsg     []string
		checkToInMsg string
	}{
		{
			name:     "Standard success case",
			email:    "newuser@example.com",
			username: "newuser",
			wantTo:   []string{"newuser@example.com"},
			wantInMsg: []string{
				"Subject: [RAuth] Welcome: Your Account is Ready",
				"Hello <strong>newuser</strong>",
				"https://auth.example.com/rauthlogin",
				"https://auth.example.com/static/favicon.png",
				"<!DOCTYPE html>",
			},
			checkToInMsg: "newuser@example.com",
		},
		{
			name:     "HTML escaping for XSS protection",
			email:    "victim@example.com",
			username: "malicious<script>alert(1)</script>",
			wantTo:   []string{"victim@example.com"},
			wantInMsg: []string{
				"malicious&lt;script&gt;alert(1)&lt;/script&gt;",
			},
			notInMsg: []string{
				"<script>",
			},
			checkToInMsg: "victim@example.com",
		},
		{
			name:     "Header injection prevention in email",
			email:    "user@example.com\r\nBcc: attacker@evil.com",
			username: "normaluser",
			wantTo:   []string{"user@example.comBcc: attacker@evil.com"},
			wantInMsg: []string{
				"To: user@example.comBcc: attacker@evil.com",
			},
			checkToInMsg: "user@example.comBcc: attacker@evil.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SendAccountCreatedNotification(tt.email, tt.username)

			assert.Equal(t, "noreply@rauth.example.com", capturedFrom)
			assert.Equal(t, tt.wantTo, capturedTo)

			// Verify no newlines in the "To:" header line within the message
			lines := strings.Split(capturedMsg, "\r\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "To: ") {
					assert.NotContains(t, line, "\r")
					assert.NotContains(t, line, "\n")
					if tt.checkToInMsg != "" {
						assert.Contains(t, line, tt.checkToInMsg)
					}
				}
			}

			for _, content := range tt.wantInMsg {
				assert.Contains(t, capturedMsg, content)
			}
			for _, content := range tt.notInMsg {
				assert.NotContains(t, capturedMsg, content)
			}
		})
	}
}
