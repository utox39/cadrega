// Package rules implements functions to:
// - detect ASCII Smuggling (obfuscation)
// - detect Typoglycemia (obfuscation)
// - extract Base64 encoded strings
// - extract hex encoded strings
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
func GetBase64ValidStrings(data string) []string {
	fullLineRegex := regexp.MustCompile(`(?m)^([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$`)
	inlineRegex := regexp.MustCompile(`base64[,:]([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?`)

	seen := make(map[string]struct{})
	var results []string

	for _, match := range append(fullLineRegex.FindAllString(data, -1), inlineRegex.FindAllString(data, -1)...) {
		if _, ok := seen[match]; !ok {
			seen[match] = struct{}{}
			results = append(results, match)
		}
	}

	return results
}

// GetHexStrings extracts hex encoded strings from data using two strategies:
//   - Full-line: lines whose entire content is a valid hex blob (even-length, at least 4 bytes)
//   - Inline: hex payloads prefixed with "0x", "\x", "hex," or "hex:"
//
// Duplicates across both strategies are removed before returning.
//
// Returns the matched hex strings, or nil if none are found.
func GetHexStrings(data string) []string {
	fullLineRegex := regexp.MustCompile(`(?m)^([0-9a-fA-F]{2}){4,}$`)
	inlineRegex := regexp.MustCompile(`(?:0x|\\x|hex[,:])[0-9a-fA-F]{2,}`)

	seen := make(map[string]struct{})
	var results []string

	for _, match := range append(fullLineRegex.FindAllString(data, -1), inlineRegex.FindAllString(data, -1)...) {
		if _, ok := seen[match]; !ok {
			seen[match] = struct{}{}
			results = append(results, match)
		}
	}

	return results
}
