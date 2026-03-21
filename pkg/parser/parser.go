// Package parser implements the parsers to extract:
// - URLs
// - Shell commands
package parser

import (
	"regexp"
)

// GetURLs extracts all the URLs from the file.
// Can return nil if no URLs are found.
func GetURLs(data []byte) []string {
	urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	return urlRegex.FindAllString(string(data), -1)
}

// GetShellCommands extracts shell commands like: curl, wget, npx and pip from the file.
// Can return nil if no shell commands are found.
func GetShellCommands(data []byte) []string {
	shRegex := regexp.MustCompile(`curl .* \| (bash|sh|source)|wget .* -O- \| bash|npx [a-z0-9-]+|pip install .*`)
	return shRegex.FindAllString(string(data), -1)
}

// GetBase64ValidStrings extracts all the valid base64 strings from the file.
// It matches both full-line base64 blobs and inline base64 with a "base64," or "base64:" prefix.
// Can return nil if no valid base64 strings are found.
func GetBase64ValidStrings(data []byte) []string {
	fullLineRegex := regexp.MustCompile(`(?m)^([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$`)
	inlineRegex := regexp.MustCompile(`base64[,:]([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?`)

	content := string(data)
	seen := make(map[string]struct{})
	var results []string

	for _, match := range append(fullLineRegex.FindAllString(content, -1), inlineRegex.FindAllString(content, -1)...) {
		if _, ok := seen[match]; !ok {
			seen[match] = struct{}{}
			results = append(results, match)
		}
	}

	return results
}
