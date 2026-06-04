package core

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestSanitizeEmailHeader_TrailingSpace(t *testing.T) {
	input := "test@example.com  "
	expected := "test@example.com"
	actual := sanitizeEmailHeader(input)
	assert.Equal(t, expected, actual, "Trailing spaces should be removed from email headers")
}
