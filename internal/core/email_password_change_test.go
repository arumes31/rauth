package core

import (
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendPasswordChangeNotification_Detailed(t *testing.T) {
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
		ip       string
		wantSub  string
		wantBody []string
	}{
		{
			name:     "Standard Password Change",
			email:    "user@example.com",
			username: "testuser",
			ip:       "1.2.3.4",
			wantSub:  "Subject: [RAuth] Security Alert: Password Changed",
			wantBody: []string{"testuser", "1.2.3.4"},
		},
		{
			name:     "HTML Escaping",
			email:    "attacker@example.com",
			username: "<script>alert(1)</script>",
			ip:       "127.0.0.1",
			wantSub:  "Subject: [RAuth] Security Alert: Password Changed",
			wantBody: []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "127.0.0.1"},
		},
		{
			name:     "IP Address Escaping",
			email:    "user@example.com",
			username: "testuser",
			ip:       "1.2.3.4<img src=x>",
			wantSub:  "Subject: [RAuth] Security Alert: Password Changed",
			wantBody: []string{"testuser", "1.2.3.4&lt;img src=x&gt;"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SendPasswordChangeNotification(tt.email, tt.username, tt.ip)

			assert.Equal(t, []string{tt.email}, capturedTo)
			assert.Contains(t, capturedMsg, tt.wantSub)
			for _, content := range tt.wantBody {
				assert.Contains(t, capturedMsg, content)
			}
		})
	}
}
