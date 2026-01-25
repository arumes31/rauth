package core

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestSendEmail_NotConfigured(t *testing.T) {
	// Ensure SMTP is not configured
	// We don't want to actually send an email in tests anyway unless mocked
	err := SendEmail("test@example.com", "Test Subject", "Test Body")
	assert.NoError(t, err) // Should return nil when not configured
}
