package core

import (
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendAccountCreatedNotification_Detailed(t *testing.T) {
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

	tests := []struct {
		name     string
		email    string
		username string
		wantSub  string
		wantBody []string
		notBody  []string
	}{
		{
			name:     "Standard Account Creation",
			email:    "newuser@example.com",
			username: "newuser",
			wantSub:  "Subject: [RAuth] Welcome: Your Account is Ready",
			wantBody: []string{
				"newuser",
				"https://rauth.example.com/rauthlogin",
				"https://rauth.example.com/static/favicon.png",
				"Welcome to RAuth",
			},
		},
		{
			name:     "HTML Escaping for XSS Prevention",
			email:    "attacker@example.com",
			username: "<script>alert('xss')</script>",
			wantSub:  "Subject: [RAuth] Welcome: Your Account is Ready",
			wantBody: []string{
				"&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
				"https://rauth.example.com/rauthlogin",
			},
			notBody: []string{
				"<script>",
			},
		},
		{
			name:     "Different Public URL",
			email:    "user@example.com",
			username: "testuser",
			wantSub:  "Subject: [RAuth] Welcome: Your Account is Ready",
			wantBody: []string{
				"https://rauth.example.com/rauthlogin",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SendAccountCreatedNotification(tt.email, tt.username)

			assert.Equal(t, "rauth@example.com", capturedFrom)
			assert.Equal(t, []string{tt.email}, capturedTo)
			assert.Contains(t, capturedMsg, tt.wantSub)
			for _, content := range tt.wantBody {
				assert.Contains(t, capturedMsg, content)
			}
			for _, content := range tt.notBody {
				assert.NotContains(t, capturedMsg, content)
			}
		})
	}
}
