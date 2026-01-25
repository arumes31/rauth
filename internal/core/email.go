package core

import (
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
	"time"
)

const emailBaseTemplate = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f7f6; }
        .container { max-width: 600px; margin: 20px auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        .header { background: #0d6efd; color: #fff; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 24px; letter-spacing: 1px; }
        .content { padding: 30px; }
        .footer { background: #f8f9fa; color: #6c757d; padding: 20px; text-align: center; font-size: 12px; }
        .btn { display: inline-block; padding: 12px 25px; background: #0d6efd; color: #fff; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 20px; }
        .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .alert-warning { background: #fff3cd; border: 1px solid #ffeeba; color: #856404; }
        .details { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; font-size: 14px; }
        .details div { margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RAuth Security</h1>
        </div>
        <div class="content">
            {{.Content}}
        </div>
        <div class="footer">
            &copy; 2026 RAuth Authentication Proxy. All rights reserved.<br>
            This is an automated security notification.
        </div>
    </div>
</body>
</html>
`

func SendEmail(to, subject, body string) error {
	cfg := LoadConfig()
	if cfg.SMTPHost == "" {
		slog.Warn("SMTP not configured, skipping email", "to", to, "subject", subject)
		return nil
	}

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	
	// If body doesn't look like HTML, wrap it in our base template
	if !strings.Contains(body, "<html>") {
		body = strings.Replace(emailBaseTemplate, "{{.Content}}", body, 1)
	}

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-version: 1.0;\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\";\r\n"+
		"\r\n"+
		"%s\r\n", cfg.SMTPFrom, to, subject, body))

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	
	err := smtp.SendMail(addr, auth, cfg.SMTPFrom, []string{to}, msg)
	if err != nil {
		slog.Error("Failed to send email", "error", err, "to", to)
		return err
	}

	slog.Info("Email sent successfully", "to", to, "subject", subject)
	return nil
}

func SendLoginNotification(email, username, ip, country string) {
	subject := "[RAuth] Security Alert: New Login Detected"
	body := fmt.Sprintf(`
		<h2>New Login Detected</h2>
		<p>Hello <strong>%s</strong>,</p>
		<p>A new login was just recorded for your account. If this was you, you can safely ignore this email.</p>
		<div class="details">
			<div><strong>Account:</strong> %s</div>
			<div><strong>IP Address:</strong> %s</div>
			<div><strong>Location:</strong> %s</div>
			<div><strong>Time:</strong> %s</div>
		</div>
		<div class="alert alert-warning">
			<strong>Wasn't you?</strong> If you don't recognize this activity, please change your password immediately and terminate all active sessions from your profile dashboard.
		</div>
		<a href="%s/rauthprofile" class="btn">Manage Account</a>
	`, username, username, ip, country, time.Now().Format("Jan 02, 2006 15:04:05 MST"), cfg.PublicURL)
	
	_ = SendEmail(email, subject, body)
}

func SendPasswordChangeNotification(email, username, ip string) {
	subject := "[RAuth] Security Alert: Password Changed"
	body := fmt.Sprintf(`
		<h2>Password Changed</h2>
		<p>Hello <strong>%s</strong>,</p>
		<p>The password for your RAuth account was recently changed.</p>
		<div class="details">
			<div><strong>IP Address:</strong> %s</div>
			<div><strong>Time:</strong> %s</div>
		</div>
		<p>If you did not perform this change, please contact your administrator immediately.</p>
	`, username, ip, time.Now().Format("Jan 02, 2006 15:04:05 MST"))
	
	_ = SendEmail(email, subject, body)
}

