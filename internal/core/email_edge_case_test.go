package core

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestSanitizeEmailHeader_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "leading space",
			input:    "  leading",
			expected: "leading",
		},
		{
			name:     "trailing space",
			input:    "trailing  ",
			expected: "trailing",
		},
		{
			name:     "both spaces",
			input:    "  both  ",
			expected: "both",
		},
		{
			name:     "inner newline",
			input:    "inner\nnewline",
			expected: "innernewline",
		},
		{
			name:     "mixed whitespace and newlines",
			input:    " \r\n  test  \n\r ",
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := sanitizeEmailHeader(tt.input)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
