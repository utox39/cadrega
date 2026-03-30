package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectBasicDAN(t *testing.T) {
	// TODO: add more test cases
	tests := []struct {
		name     string
		input    string
		wantAny  bool // true = expect at least one match
		contains string
	}{
		{
			name:     "exact DAN keyword",
			input:    "DAN",
			wantAny:  true,
			contains: "DAN",
		},
		{
			name:     "case-insensitive match",
			input:    "dan",
			wantAny:  true,
			contains: "DAN",
		},
		{
			name:     "mixed-case match",
			input:    "you can DaN",
			wantAny:  true,
			contains: "DAN",
		},
		{
			name:     "exact simulate keyword",
			input:    "simulate",
			wantAny:  true,
			contains: "simulate",
		},
		{
			name:     "exact ignore previous instructions keyword",
			input:    "ignore previous instructions",
			wantAny:  true,
			contains: "ignore previous instructions",
		},
		{
			name:    "no DAN content",
			input:   "Hello, how are you?",
			wantAny: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantAny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectBasicDAN(tt.input)

			if tt.wantAny {
				assert.NotEmpty(t, result)
				if tt.contains != "" {
					assert.Contains(t, result, tt.contains)
				}
			} else {
				assert.Empty(t, result)
			}
		})
	}
}
