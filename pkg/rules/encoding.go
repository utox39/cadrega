// Package rules implements functions to:
// - detect ASCII Smuggling (obfuscation)
// - detect Typoglycemia (obfuscation)
// - detect Base64 encoded strings
// - detect hex encoded strings
// - detect ASCII85 encoded strings
// - etc.
package rules

import "regexp"

// DetectBase64ValidStrings extracts base64 encoded strings from data using two strategies:
//   - Full-line: lines whose entire content is a valid base64 blob (common for
//     encoded instruction blocks smuggled into LLM prompts)
//   - Inline: base64 payloads prefixed with "base64," or "base64:" (e.g. data URIs)
//
// Duplicates across both strategies are removed before returning.
//
// Returns the matched base64 strings, or nil if none are found.
func DetectBase64ValidStrings(data string) []string {
	fullLineRegex := regexp.MustCompile(`(?m)^([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$`)
	inlineRegex := regexp.MustCompile(`b[ase]{0,3}64[,:]([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?`)

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

// DetectHexStrings extracts hex encoded strings from data using two strategies:
//   - Full-line: lines whose entire content is a valid hex blob (even-length, at least 4 bytes)
//   - Inline: hex payloads prefixed with "0x", "\x", "hex," or "hex:"
//
// Duplicates across both strategies are removed before returning.
//
// Returns the matched hex strings, or nil if none are found.
func DetectHexStrings(data string) []string {
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

// DetectASCII85 extracts ASCII85-encoded strings from data by looking for the
// standard `<~` and `~>` delimiters used by implementations such as Adobe PostScript
// and PDF. The content between the delimiters may include whitespace, which is
// valid and ignored during decoding.
//
// Returns the matched delimited ASCII85 strings, or nil if none are found.
func DetectASCII85(data string) []string {
	ascii85WithDelimitersRegex := regexp.MustCompile(`<~[!-uz\s]+~>`)
	return ascii85WithDelimitersRegex.FindAllString(data, -1)
}

// DetectASCII85WithoutDelimiters extracts ASCII85-encoded strings from data
// without relying on `<~` / `~>` delimiters. It matches runs of at least 20
// consecutive ASCII85 characters (charset: `!` to `u` and `z`).
//
// Returns the matched ASCII85 strings, or nil if none are found.
func DetectASCII85WithoutDelimiters(data string) []string {
	// {20,} matches sequences of at least 20 consecutive ASCII85 characters.
	// This threshold balances false positives and detection coverage:
	// - high enough to avoid matching common text (punctuation, lowercase letters
	//   a-u and digits all fall within the ASCII85 charset, but rarely appear
	//   in uninterrupted runs of 20+ characters in natural language);
	// - low enough to catch meaningful payloads (encoding just 10 bytes of data
	//   already produces a 13-character ASCII85 string, so 20 characters
	//   represent a conservative but realistic lower bound).
	ascii85RawRegex := regexp.MustCompile(`[!-uz]{20,}`)

	return ascii85RawRegex.FindAllString(data, -1)
}
