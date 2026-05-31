package core

import (
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSend2FAModifiedNotification_Detailed(t *testing.T) {
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_FROM", "rauth@example.com")
	t.Setenv("PUBLIC_URL", "https://rauth.example.com")

	var capturedTo []string
	var capturedMsg string

	origSendMail := sendMail
	defer func() { sendMail = origSendMail }()

	sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		capturedTo = to
		capturedMsg = string(msg)
		return nil
	}

	tests := []struct {
		name     string
		email    string
		username string
		action   string
		ip       string
		wantSub  string
		wantBody []string
	}{
		{
			name:     "Standard Enabled",
			email:    "user@example.com",
			username: "testuser",
			action:   "Enabled",
			ip:       "1.2.3.4",
			wantSub:  "Subject: [RAuth] Security Alert: 2FA Enabled",
			wantBody: []string{"testuser", "Enabled", "1.2.3.4"},
		},
		{
			name:     "HTML Escaping",
			email:    "attacker@example.com",
			username: "<script>alert(1)</script>",
			action:   "<b>Disabled</b>",
			ip:       "127.0.0.1",
			wantSub:  "Subject: [RAuth] Security Alert: 2FA <b>Disabled</b>", // Note: sanitizeEmailHeader doesn't strip HTML from subject, only newlines
			wantBody: []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;b&gt;Disabled&lt;/b&gt;", "127.0.0.1"},
		},
		{
			name:     "Header Injection Prevention",
			email:    "user@example.com",
			username: "testuser",
			action:   "Enabled\r\nBcc: spy@evil.com",
			ip:       "1.2.3.4",
			wantSub:  "Subject: [RAuth] Security Alert: 2FA EnabledBcc: spy@evil.com",
			wantBody: []string{"testuser", "Enabled\r\nBcc: spy@evil.com", "1.2.3.4"}, // Body escaping is separate
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Send2FAModifiedNotification(tt.email, tt.username, tt.action, tt.ip, "Test Device")

			assert.Equal(t, []string{tt.email}, capturedTo)
			assert.Contains(t, capturedMsg, tt.wantSub)
			assert.Contains(t, capturedMsg, "Test Device")
			for _, content := range tt.wantBody {
				assert.Contains(t, capturedMsg, content)
			}
		})
	}
}
