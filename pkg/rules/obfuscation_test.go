package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectASCIISmuggling(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid ASCII smuggling",
			input:    "\U000E0048\U000E0065\U000E006C\U000E006C\U000E006F\U000E002C\U000E0020\U000E0077\U000E006F\U000E0072\U000E006C\U000E0064\U000E0021",
			expected: "Hello, world!",
		},
		{
			name:     "no smuggling",
			input:    "Hello, world!",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectASCIISmuggling(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
