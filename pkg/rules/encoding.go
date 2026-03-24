// Package rules implements functions to:
// - detect ASCII Smuggling (obfuscation)
// - detect Typoglycemia (obfuscation)
// - extract Base64 encoded strings
// - etc.
package rules

import "regexp"

// GetBase64ValidStrings extracts base64 encoded strings from data using two strategies:
//   - Full-line: lines whose entire content is a valid base64 blob (common for
//     encoded instruction blocks smuggled into LLM prompts)
//   - Inline: base64 payloads prefixed with "base64," or "base64:" (e.g. data URIs)
//
// Duplicates across both strategies are removed before returning.
//
// Returns the matched base64 strings, or nil if none are found.
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
