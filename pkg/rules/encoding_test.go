package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectBase64ValidStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAny  bool
		contains []string
	}{
		{
			name:     "empty string",
			input:    "",
			wantAny:  false,
			contains: nil,
		},
		{
			name:     "full-line valid base64 without prefix",
			input:    "SGVsbG8sIFdvcmxkIQ==", // Hello, World!
			wantAny:  true,
			contains: []string{"SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "full-line no base64",
			input:    "Hello, World!",
			wantAny:  false,
			contains: nil,
		},
		{
			name:     "in-line base64 with prefix base64",
			input:    "base64:SGVsbG8sIFdvcmxkIQ==", // Hello, World!
			wantAny:  true,
			contains: []string{"base64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "in-line base64 with space after the prefix base64",
			input:    "base64: SGVsbG8sIFdvcmxkIQ==", // Hello, World!
			wantAny:  true,
			contains: []string{"base64: SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "in-line base64 with prefix b64",
			input:    "b64:SGVsbG8sIFdvcmxkIQ==", // Hello, World!
			wantAny:  true,
			contains: []string{"b64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "in-line base64 with space after the prefix b64",
			input:    "b64: SGVsbG8sIFdvcmxkIQ==", // Hello, World!
			wantAny:  true,
			contains: []string{"b64: SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix base64 (ase)",
			input:    "base64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"base64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix baes64 (aes)",
			input:    "baes64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"baes64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bsae64 (sae)",
			input:    "bsae64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bsae64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bsea64 (sea)",
			input:    "bsea64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bsea64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix beas64 (eas)",
			input:    "beas64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"beas64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix besa64 (esa)",
			input:    "besa64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"besa64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bas64 (as)",
			input:    "bas64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bas64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bae64 (ae)",
			input:    "bae64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bae64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bsa64 (sa)",
			input:    "bsa64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bsa64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bse64 (se)",
			input:    "bse64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bse64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bea64 (ea)",
			input:    "bea64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bea64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bes64 (es)",
			input:    "bes64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bes64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix ba64 (a)",
			input:    "ba64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"ba64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix bs64 (s)",
			input:    "bs64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"bs64:SGVsbG8sIFdvcmxkIQ=="},
		},
		{
			name:     "prefix be64 (e)",
			input:    "be64:SGVsbG8sIFdvcmxkIQ==",
			wantAny:  true,
			contains: []string{"be64:SGVsbG8sIFdvcmxkIQ=="},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectBase64ValidStrings(tt.input)

			if tt.wantAny {
				assert.NotEmpty(t, result)
				if tt.contains != nil {
					for _, c := range tt.contains {
						assert.Contains(t, result, c)
					}
				}
			} else {
				assert.Empty(t, result)
			}
		})
	}
}
