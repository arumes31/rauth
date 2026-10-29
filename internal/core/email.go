package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"
)

var sendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return sendMailTLS(LoadConfig().SMTPTLSMode(), addr, a, from, to, msg)
}

// smtpTimeout bounds connecting to the SMTP server and each exchange.
const smtpTimeout = 30 * time.Second

// sendMailTLS is smtp.SendMail with a mandatory TLS policy. smtp.SendMail
// only upgrades when the server advertises STARTTLS, so an active attacker
// who strips that line gets the notification in clear text (with
// credentials, PlainAuth refuses, but unauthenticated relays would send).
//
// mode "tls" uses implicit TLS (port 465), "starttls" requires a successful
// STARTTLS before anything else is sent, and "none" keeps the old
// opportunistic behaviour for plain-text relays on a trusted network.
func sendMailTLS(mode, addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: smtpTimeout}

	var conn net.Conn
	if mode == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()

	if mode != "tls" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return err
			}
		} else if mode != "none" {
			return errors.New("smtp: server does not offer STARTTLS (set SMTP_TLS=none only for a trusted plain-text relay)")
		}
	}
	if a != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("smtp: server doesn't support AUTH")
		}
		if err := c.Auth(a); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

const emailBaseTemplate = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f7f6; }
        .container { max-width: 600px; margin: 20px auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        .header { background: #dc3545; color: #fff; padding: 30px; text-align: center; }
        .header img { display: block; margin: 0 auto 10px auto; border-radius: 10px; }
        .header h1 { margin: 0; font-size: 24px; letter-spacing: 1px; }
        .content { padding: 30px; }
        .footer { background: #f8f9fa; color: #6c757d; padding: 20px; text-align: center; font-size: 12px; }
        .btn { display: inline-block; padding: 12px 25px; background: #dc3545; color: #fff; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 20px; }
        .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .alert-warning { background: #fff3cd; border: 1px solid #ffeeba; color: #856404; }
        .details { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; font-size: 14px; }
        .details div { margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="{{.LogoURL}}" alt="RAuth Logo" width="64" height="64">
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

func sanitizeEmailHeader(s string) string {
	// Remove any carriage returns or newlines to prevent header injection
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

func SendEmail(to, subject, body string) error {
	cfg := LoadConfig()
	if cfg.SMTPHost == "" {
		slog.Warn("SMTP not configured, skipping email", "to", to, "subject", subject)
		return nil
	}

	to = sanitizeEmailHeader(to)
	subject = sanitizeEmailHeader(subject)

	// Only authenticate when credentials are configured; otherwise an
	// unauthenticated relay would be sent an empty-credential AUTH and refuse.
	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}

	// If body doesn't look like HTML, wrap it in our base template
	if !strings.Contains(body, "<html>") {
		body = strings.Replace(emailBaseTemplate, "{{.Content}}", body, 1)
	}

	logoURL := cfg.PublicURL + "/static/favicon.png"
	body = strings.ReplaceAll(body, "{{.LogoURL}}", logoURL)

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-version: 1.0;\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\";\r\n"+
		"\r\n"+
		"%s\r\n", cfg.SMTPFrom, to, subject, body))

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)

	err := sendMail(addr, auth, cfg.SMTPFrom, []string{to}, msg)

	if err != nil {
		slog.Error("Failed to send email", "error", err, "to", to)
		return err
	}

	slog.Info("Email sent successfully", "to", to, "subject", subject)
	return nil
}

func SendLoginNotification(email, username, ip, country, device string) {
	subject := "[RAuth] Security Alert: New Login Detected"

	eUsername := html.EscapeString(username)
	eIP := html.EscapeString(ip)
	eCountry := html.EscapeString(country)
	eDevice := html.EscapeString(device)

	body := fmt.Sprintf(`
		<h2>New Login Detected</h2>
		<p>Hello <strong>%s</strong>,</p>
		<p>A new login was just recorded for your account. If this was you, you can safely ignore this email.</p>
		<div class="details">
			<div><strong>Account:</strong> %s</div>
			<div><strong>Device:</strong> %s</div>
			<div><strong>IP Address:</strong> %s</div>
			<div><strong>Location:</strong> %s</div>
			<div><strong>Time:</strong> %s</div>
		</div>
		<div class="alert alert-warning">
			<strong>Wasn't you?</strong> If you don't recognize this activity, please change your password immediately and terminate all active sessions from your profile dashboard.
		</div>
		<a href="%s/rauthprofile" class="btn">Manage Account</a>
	`, eUsername, eUsername, eDevice, eIP, eCountry, time.Now().Format("Jan 02, 2006 15:04:05 MST"), LoadConfig().PublicURL)

	_ = SendEmail(email, subject, body)
}

func SendPasswordChangeNotification(email, username, ip, device string) {
	subject := "[RAuth] Security Alert: Password Changed"

	eUsername := html.EscapeString(username)
	eIP := html.EscapeString(ip)
	eDevice := html.EscapeString(device)

	body := fmt.Sprintf(`
		<h2>Password Changed</h2>
		<p>Hello <strong>%s</strong>,</p>
		<p>The password for your RAuth account was recently changed.</p>
		<div class="details">
			<div><strong>Device:</strong> %s</div>
			<div><strong>IP Address:</strong> %s</div>
			<div><strong>Time:</strong> %s</div>
		</div>
		<p>If you did not perform this change, please contact your administrator immediately.</p>
	`, eUsername, eDevice, eIP, time.Now().Format("Jan 02, 2006 15:04:05 MST"))

	_ = SendEmail(email, subject, body)
}

func SendAccountCreatedNotification(email, username string) {
	subject := "[RAuth] Welcome: Your Account is Ready"

	eUsername := html.EscapeString(username)

	body := fmt.Sprintf(`
		<h2>Welcome to RAuth</h2>
		<p>Hello <strong>%s</strong>,</p>
		<p>An administrator has created an account for you on the RAuth Authentication Proxy.</p>
		<p>You can now log in using your provided credentials at the link below.</p>
		<a href="%s/rauthlogin" class="btn">Login to RAuth</a>
		<p style="margin-top: 20px; font-size: 13px; color: #666;">
			Note: For your security, please change your password and set up 2FA after your first login.
		</p>
	`, eUsername, LoadConfig().PublicURL)

	_ = SendEmail(email, subject, body)
}

type TwoFactorNotificationOptions struct {
	Email    string
	Username string
	Action   string
	IP       string
	Device   string
}

func Send2FAModifiedNotification(opts TwoFactorNotificationOptions) {
	subject := sanitizeEmailHeader(fmt.Sprintf("[RAuth] Security Alert: 2FA %s", opts.Action))

	eUsername := html.EscapeString(opts.Username)
	eAction := html.EscapeString(opts.Action)
	eIP := html.EscapeString(opts.IP)
	eDevice := html.EscapeString(opts.Device)

	body := fmt.Sprintf(`
		<h2>Two-Factor Authentication %s</h2>
		<p>Hello <strong>%s</strong>,</p>
		<p>A change was made to your security settings: <strong>Two-Factor Authentication was %s</strong>.</p>
		<div class="details">
			<div><strong>Action:</strong> %s</div>
			<div><strong>Device:</strong> %s</div>
			<div><strong>IP Address:</strong> %s</div>
			<div><strong>Time:</strong> %s</div>
		</div>
		<div class="alert alert-warning">
			<strong>Wasn't you?</strong> If you did not authorize this change, your account may be compromised. Please contact your administrator immediately.
		</div>
	`, eAction, eUsername, eAction, eAction, eDevice, eIP, time.Now().Format("Jan 02, 2006 15:04:05 MST"))

	_ = SendEmail(opts.Email, subject, body)

}
