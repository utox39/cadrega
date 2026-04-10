// Package parser implements functions to:
// - extract URLs
// - extract Shell commands
package parser

import (
	"regexp"
)

// GetURLs extracts all HTTP and HTTPS URLs from data.
//
// Returns the matched URLs, or nil if none are found.
func GetURLs(data string) []string {
	urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	return urlRegex.FindAllString(data, -1)
}

// GetShellCommands extracts potentially dangerous shell command patterns from data.
// Detected patterns include:
//   - curl ... | bash/sh/source  (remote script execution via curl)
//   - wget ... -O- | bash        (remote script execution via wget)
//   - npx <package>              (arbitrary npm package execution)
//   - pip install ...            (arbitrary Python package installation)
//
// Returns the matched commands, or nil if none are found.
func GetShellCommands(data string) []string {
	shRegex := regexp.MustCompile(`curl .* \| (bash|sh|source)|wget .* -O- \| bash|npx [a-z0-9-]+|pip install .*`)
	return shRegex.FindAllString(data, -1)
}
