// Package rules implements functions to:
// - detect ASCII Smuggling (obfuscation)
// - detect Typoglycemia (obfuscation)
// - extract Base64 encoded strings
// - etc.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/utox39/cadrega/pkg/findings"
)

// TODO: add more fuzzy patterns
func getFuzzyPatterns() []string {
	return []string{
		"ignore", "bypass", "override", "reveal", "delete", "system",
	}
}

// DetectASCIISmuggling scans data for Unicode Tag characters (U+E0000–U+E007F),
// a technique known as ASCII Smuggling where invisible tag characters encode
// hidden text that may be invisible to users but readable by LLMs.
//
// Each tag character is converted to its visible ASCII equivalent by subtracting
// 0xE0000 from the rune value (e.g. U+E0048 -> 'H').
//
// Returns the decoded visible string if tag characters are found, or an empty
// string if no smuggled content is detected.
func DetectASCIISmuggling(data string) string {
	var result strings.Builder

	for _, r := range data {
		if (r >= 0xE0000) && (r <= 0xE007F) {
			result.WriteRune(r - 0xE0000)
		}
	}

	return result.String()
}

type ASCIISmuggling struct {
	Data string
}

func (as ASCIISmuggling) ID() string {
	return "OBF001"
}

func (as ASCIISmuggling) Name() string {
	return "ASCII Smuggling"
}

func (as ASCIISmuggling) Detect() ([]findings.Finding, error) {
	result := DetectASCIISmuggling(as.Data)

	if len(result) == 0 {
		return nil, nil
	}

	// To respect the return type defined in the `Rule` interface
	f := []findings.Finding{
		{
			ID:       as.ID(),
			Name:     as.Name(),
			Message:  "ASCII Smuggling. It uses invisible characters that can be used to perform prompt injection",
			Evidence: fmt.Sprintf("visible: '%s'", result),
			Severity: findings.High,
		},
	}

	return f, nil
}

// DetectTypoglycemiaFuzzy detects typoglycemia in data using fuzzy string
// matching against a set of known sensitive keywords (e.g. "ignore", "bypass").
// Typoglycemia exploits the brain's ability to read scrambled words, and can be
// used to smuggle instructions past keyword-based filters (e.g. "ignroe" instead
// of "ignore").
//
// Words shorter than 3 characters are skipped to reduce noise.
//
// Returns the matched words, or nil if none are found.
//
// Note: fuzzy matching may produce false positives compared to the sort-based
// approach in DetectTypoglycemia, but is significantly faster.
func DetectTypoglycemiaFuzzy(data string) []string {
	words := strings.Split(data, " ")
	patterns := getFuzzyPatterns()

	var result []string

	for _, word := range words {
		if len(word) < 3 {
			continue
		}
		if len(fuzzy.Find(word, patterns)) > 0 {
			result = append(result, word)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// DetectTypoglycemiaFuzzyIgnoreCase is a case-insensitive version of DetectTypoglycemiaFuzzy
func DetectTypoglycemiaFuzzyIgnoreCase(data string) []string {
	words := strings.Split(data, " ")
	patterns := getFuzzyPatterns()

	var result []string

	for _, word := range words {
		if len(word) < 3 {
			continue
		}
		if len(fuzzy.FindFold(word, patterns)) > 0 {
			result = append(result, word)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// DetectTypoglycemia detects typoglycemia in data using a sort-based character
// comparison against a set of known sensitive keywords. A word is considered a
// typoglycemia variant of a target if it has the same length, the same first and
// last characters, and the same set of characters (regardless of middle order).
//
// Words shorter than 3 characters are skipped.
//
// Returns the matched words, or nil if none are found.
func DetectTypoglycemia(data string) []string {
	words := strings.Split(data, " ")
	patterns := getFuzzyPatterns()

	var result []string

	for _, word := range words {
		if isTypoglycemia(word, patterns) {
			result = append(result, word)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// DetectTypoglycemiaIgnoreCase is a case-insensitive version of DetectTypoglycemia
func DetectTypoglycemiaIgnoreCase(data string) []string {
	return DetectTypoglycemia(strings.ToLower(data))
}

// isTypoglycemia returns true if s is a typoglycemia variant of any string in
// targets, otherwise it returns false. A match requires equal length (>= 3), identical first and last
// characters, and the same multiset of characters as the target.
//
// Inspired by:
// https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html#input-validation-and-sanitization
func isTypoglycemia(s string, targets []string) bool {
	splittedS := strings.Split(s, "")
	sort.Strings(splittedS)
	splittedSJoined := strings.Join(splittedS, "")

	for _, t := range targets {
		if (len(s) != len(t)) || len(s) < 3 {
			continue
		}

		sort.Strings(strings.Split(t, ""))

		if (s[0] == t[0]) && (s[len(s)-1] == t[len(t)-1]) && (splittedSJoined == t) {
			return true
		}

	}

	return false
}

type Typoglycemia struct {
	Data       string
	Fuzzy      bool
	IgnoreCase bool
	Join       bool // Join the individual strings into a single string, separated by spaces
}

func (t Typoglycemia) ID() string {
	return "OBF002"
}

func (t Typoglycemia) Name() string {
	return "Typoglycemia"
}

func (t Typoglycemia) Detect() ([]findings.Finding, error) {
	var result []string

	if t.Fuzzy {
		if t.IgnoreCase {
			result = DetectTypoglycemiaFuzzyIgnoreCase(t.Data)
		} else {
			result = DetectTypoglycemiaFuzzy(t.Data)
		}
	} else if t.IgnoreCase {
		result = DetectTypoglycemiaIgnoreCase(t.Data)
	} else {
		result = DetectTypoglycemia(t.Data)
	}

	if result == nil {
		return nil, nil
	}

	if t.Join {
		resultJoined := strings.Join(result, " ")
		// To respect the return type defined in the `Rule` interface
		return []findings.Finding{
			{
				ID:       t.ID(),
				Name:     t.Name(),
				Message:  "Typoglycemia detected. It can be used to perform prompt injection",
				Evidence: fmt.Sprintf("typoglycemia: '%s' ", resultJoined),
				Severity: findings.High,
			},
		}, nil
	}

	f := make([]findings.Finding, 0)

	for _, r := range result {
		f = append(f, findings.Finding{
			ID:       t.ID(),
			Name:     t.Name(),
			Message:  "Typoglycemia detected. It can be used to perform prompt injection",
			Evidence: fmt.Sprintf("typoglycemia: '%s' ", r),
			Severity: findings.High,
		})
	}

	return f, nil
}
