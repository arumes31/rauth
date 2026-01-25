package core

import (
	"fmt"
	"log/slog"
	"net/smtp"
)

func SendEmail(to, subject, body string) error {
	cfg := LoadConfig()
	if cfg.SMTPHost == "" {
		slog.Warn("SMTP not configured, skipping email", "to", to, "subject", subject)
		return nil
	}

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	
	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", to, subject, body))

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	
	err := smtp.SendMail(addr, auth, cfg.SMTPFrom, []string{to}, msg)
	if err != nil {
		slog.Error("Failed to send email", "error", err, "to", to)
		return err
	}

	slog.Info("Email sent successfully", "to", to, "subject", subject)
	return nil
}
