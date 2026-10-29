package core

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plainSMTPServer accepts one connection, never offers STARTTLS (as after an
// attacker stripped it) and reports every command the client sent.
func plainSMTPServer(t *testing.T) (string, <-chan []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	cmds := make(chan []string, 1)
	go func() {
		var seen []string
		defer func() { cmds <- seen }()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		write("220 test ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					write("250 queued")
				}
				continue
			}
			seen = append(seen, strings.ToUpper(strings.SplitN(line, " ", 2)[0]))
			switch {
			case strings.HasPrefix(strings.ToUpper(line), "EHLO"):
				write("250-test")
				write("250 8BITMIME")
			case strings.EqualFold(line, "DATA"):
				inData = true
				write("354 go ahead")
			case strings.EqualFold(line, "QUIT"):
				write("221 bye")
				return
			default:
				write("250 ok")
			}
		}
	}()
	return ln.Addr().String(), cmds
}

func TestSendMailTLSRequiresStartTLS(t *testing.T) {
	addr, cmds := plainSMTPServer(t)
	err := sendMailTLS("starttls", addr, nil, "from@example.com", []string{"to@example.com"}, []byte("Subject: x\r\n\r\nsecret"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "STARTTLS")
	assert.NotContains(t, <-cmds, "MAIL", "nothing may be sent without TLS")

	addr, cmds = plainSMTPServer(t)
	require.NoError(t, sendMailTLS("none", addr, nil, "from@example.com", []string{"to@example.com"}, []byte("Subject: x\r\n\r\nhi")))
	assert.Contains(t, <-cmds, "DATA", "SMTP_TLS=none keeps delivering to a plain relay")
}

func TestSMTPTLSMode(t *testing.T) {
	assert.Equal(t, "starttls", (&Config{SMTPPort: 587}).SMTPTLSMode())
	assert.Equal(t, "starttls", (&Config{SMTPPort: 25}).SMTPTLSMode())
	assert.Equal(t, "tls", (&Config{SMTPPort: 465}).SMTPTLSMode())
	assert.Equal(t, "none", (&Config{SMTPPort: 25, SMTPTLS: "none"}).SMTPTLSMode())
	assert.Equal(t, "starttls", (&Config{SMTPPort: 25, SMTPTLS: "bogus"}).SMTPTLSMode(), "unknown values must not mean plain text")
}
