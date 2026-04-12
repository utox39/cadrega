package rules

import "strings"

// Basic DAN; detectable through static analysis
// TODO: maybe we should read from an external file (+ easier to update, - more overhead)
func getDANKeywords() []string {
	// TODO: change to map[string]int - [keyword]score (?)
	return []string{
		// Alternative identity
		"do anything now",
		"DAN",
		"STAN", // "Strive To Avoid Norms"
		"DUDE",
		"AIM", // "Always Intelligent and Machiavellian"
		"JAILBROKEN",
		"BetterDAN",
		"EvilBot",

		// Enable dummy mode
		"developer mode",
		"jailbreak mode",
		"unrestricted mode",
		"god mode",
		"no restrictions",
		"without restrictions",
		"ignore your training",
		"ignore your guidelines",
		"ignore your programming",
		"bypass your restrictions",
		"pretend you have no restrictions",

		// In-person assignment
		"you are now",
		"act as",
		"pretend to be",
		"roleplay as",
		"simulate",
		"from now on you will",
		"your new persona",
		"you have been freed",
		"you are no longer",
		"imagine you are",
		"imagine being",
		"imagine that you are",

		// Explicit override instructions
		"ignore previous instructions",
		"ignore all previous",
		"disregard your instructions",
		"disregard previous",
		"forget your instructions",
		"override your",
		"your true self",
		"your real instructions are",

		// Double response framing
		"[CLASSIC]",
		"[JAILBREAK]",
		"[GPT]",
		"[DAN]",
		"stay DAN",
		"stay in character",
		"remain in character",
	}
}

// DetectDAN scans data for DAN (Do Anything Now) prompt injection patterns,
// a class of jailbreak attacks that attempt to bypass an LLM's safety guidelines
// by assigning it an alternative identity or overriding its instructions.
//
// Returns the matched keywords and nil error, or nil and nil if none are found.
func DetectDAN(data string) ([]string, error) {
	// NOTE: At the moment we detect basic DAN only
	return detectBasicDAN(data), nil
}

// detectBasicDAN performs case-insensitive substring matching of data against
// a set of known static DAN keywords (see getDANKeywords). It covers patterns
// such as alternative identity assignment ("act as", "DAN"), mode-enabling
// phrases ("developer mode", "god mode"), and explicit instruction overrides
// ("ignore previous instructions").
//
// Returns the matched keywords, or nil if data is empty or no matches are found.
func detectBasicDAN(data string) []string {
	if len(data) == 0 {
		return nil
	}

	lower := strings.ToLower(data)
	var result []string
	for _, kw := range getDANKeywords() {
		if strings.Contains(lower, strings.ToLower(kw)) {
			result = append(result, kw)
		}
	}
	return result
}
