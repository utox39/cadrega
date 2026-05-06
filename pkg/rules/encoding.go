// Package rules implements functions to:
// - detect ASCII Smuggling (obfuscation)
// - detect Typoglycemia (obfuscation)
// - detect Base64 encoded strings
// - detect hex encoded strings
// - detect ASCII85 encoded strings
// - etc.
package rules

import (
	"encoding/ascii85"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/utox39/cadrega/pkg/findings"
)

var (
	b64FullLineRegex = regexp.MustCompile(`(?m)^([A-Za-z0-9]{4}){4,}([A-Za-z0-9\+\/]{3}=|[A-Za-z0-9\+\/]{2}==)?$`)
	b64InlineRegex   = regexp.MustCompile(`(b[ase]{0,3}64[,:]\s*)?([A-Za-z0-9\+\/]{4}){4,}([A-Za-z0-9]{3}=|[A-Za-z0-9\+\/]{2}==)?`)
	b64PrefixRegex   = regexp.MustCompile(`^b[ase]{0,3}64[,:]\s*`)

	hexFullLineRegex = regexp.MustCompile(`(?m)^([0-9a-fA-F]{2}){4,}$`)
	hexInlineRegex   = regexp.MustCompile(`(?:0x|\\x|hex[,:]\s*|hex\s+)[0-9a-fA-F]{16,}`)
	hexPrefixRegex   = regexp.MustCompile(`^(?:0x|\\x|hex[,:]\s*|hex\s+)`)

	ascii85WithDelimitersRegex = regexp.MustCompile(`<~[!-uz\s]+~>`)
	// {20,} matches sequences of at least 20 consecutive ASCII85 characters.
	// This threshold balances false positives and detection coverage:
	// - high enough to avoid matching common text (punctuation, lowercase letters
	//   a-u and digits all fall within the ASCII85 charset, but rarely appear
	//   in uninterrupted runs of 20+ characters in natural language);
	// - low enough to catch meaningful payloads (encoding just 10 bytes of data
	//   already produces a 13-character ASCII85 string, so 20 characters
	//   represent a conservative but realistic lower bound).
	ascii85RawRegex = regexp.MustCompile(`[!-uz]{20,}`)
)

// DetectBase64Strings extracts base64 encoded strings from data using two strategies:
//   - Full-line: lines whose entire content is a valid base64 blob (common for
//     encoded instruction blocks smuggled into LLM prompts)
//   - Inline: base64 payloads prefixed with "base64,", "base64:", "b64,", "b64:", etc. (e.g. data URIs)
//
// Duplicates across both strategies are removed before returning.
//
// Returns the matched base64 strings, or nil if none are found.
func DetectBase64Strings(data string) []string {
	seen := make(map[string]struct{})
	var results []string

	for _, match := range append(b64FullLineRegex.FindAllString(data, -1), b64InlineRegex.FindAllString(data, -1)...) {
		if _, ok := seen[match]; !ok {
			seen[match] = struct{}{}
			results = append(results, match)
		}
	}

	return results
}

type Base64Encoding struct {
	Data string
}

func (b64 Base64Encoding) ID() string {
	return "ENC001"
}

func (b64 Base64Encoding) Name() string {
	return "Base64 Encoded Strings"
}

func (b64 Base64Encoding) Detect() ([]findings.Finding, error) {
	result := DetectBase64Strings(b64.Data)

	if result == nil {
		return nil, nil
	}

	f := make([]findings.Finding, 0)

	for _, r := range result {
		payload := b64PrefixRegex.ReplaceAllString(r, "")
		dec, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, err
		}

		f = append(f, findings.Finding{
			ID:       b64.ID(),
			Name:     b64.Name(),
			Message:  "Base64 string detected. It can be used to perform prompt injection",
			Evidence: fmt.Sprintf("base64: '%s' - decoded: '%s'", r, string(dec)),
			Severity: findings.High,
		})
	}

	return f, nil
}

// DetectHexStrings extracts hex encoded strings from data using two strategies:
//   - Full-line: lines whose entire content is a valid hex blob (even-length, at least 4 bytes)
//   - Inline: hex payloads prefixed with "0x", "\x", "hex,", "hex:", "hex ", "hex: "
//
// Duplicates across both strategies are removed before returning.
//
// Returns the matched hex strings, or nil if none are found.
func DetectHexStrings(data string) []string {
	seen := make(map[string]struct{})
	var results []string

	for _, match := range append(hexFullLineRegex.FindAllString(data, -1), hexInlineRegex.FindAllString(data, -1)...) {
		if _, ok := seen[match]; !ok {
			seen[match] = struct{}{}
			results = append(results, match)
		}
	}

	return results
}

type HexEncoding struct {
	Data string
}

func (h HexEncoding) ID() string {
	return "ENC002"
}

func (h HexEncoding) Name() string {
	return "Hex Encoded Strings"
}

func (h HexEncoding) Detect() ([]findings.Finding, error) {
	result := DetectHexStrings(h.Data)

	if result == nil {
		return nil, nil
	}

	f := make([]findings.Finding, 0)

	for _, r := range result {
		payload := hexPrefixRegex.ReplaceAllString(r, "")
		dec, err := hex.DecodeString(payload)
		if err != nil {
			return nil, err
		}

		f = append(f, findings.Finding{
			ID:       h.ID(),
			Name:     h.Name(),
			Message:  "Hex string detected. It can be used to perform prompt injection",
			Evidence: fmt.Sprintf("hex: '%s' - decoded: '%s'", r, string(dec)),
			Severity: findings.High,
		})
	}

	return f, nil
}

// DetectASCII85Strings extracts ASCII85-encoded strings from data by looking for the
// standard `<~` and `~>` delimiters used by implementations such as Adobe PostScript
// and PDF. The content between the delimiters may include whitespace, which is
// valid and ignored during decoding.
//
// Returns the matched delimited ASCII85 strings, or nil if none are found.
func DetectASCII85Strings(data string) []string {
	return ascii85WithDelimitersRegex.FindAllString(data, -1)
}

// DetectASCII85StringsWithoutDelimiters extracts ASCII85-encoded strings from data
// without relying on `<~` / `~>` delimiters. It matches runs of at least 20
// consecutive ASCII85 characters (charset: `!` to `u` and `z`).
//
// Returns the matched ASCII85 strings, or nil if none are found.
func DetectASCII85StringsWithoutDelimiters(data string) []string {
	return ascii85RawRegex.FindAllString(data, -1)
}

type ASCII85Encoding struct {
	Data              string
	WithoutDelimiters bool
}

func (a85 ASCII85Encoding) ID() string {
	return "ENC003"
}

func (a85 ASCII85Encoding) Name() string {
	return "ASCII85 Encoded Strings"
}

func (a85 ASCII85Encoding) Detect() ([]findings.Finding, error) {
	var result []string

	if a85.WithoutDelimiters {
		result = DetectASCII85StringsWithoutDelimiters(a85.Data)
	} else {
		result = DetectASCII85Strings(a85.Data)
	}

	if result == nil {
		return nil, nil
	}

	f := make([]findings.Finding, 0)

	for _, r := range result {
		if !a85.WithoutDelimiters {
			r = strings.ReplaceAll(r, "<~", "")
			r = strings.ReplaceAll(r, "~>", "")
		}

		dst := make([]byte, len(r))
		ndst, _, err := ascii85.Decode(dst, []byte(r), true)
		if err != nil {
			return nil, err
		}
		dec := dst[:ndst]

		f = append(f, findings.Finding{
			ID:       a85.ID(),
			Name:     a85.Name(),
			Message:  "ASCII85 string detected. It can be used to perform prompt injection",
			Evidence: fmt.Sprintf("ASCII85: '%s' - decoded: '%s'", r, string(dec)),
			Severity: findings.High,
		})
	}

	return f, nil
}
