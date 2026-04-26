package rules

import (
	"fmt"
	"regexp"
	"sync"
	"unicode"

	"github.com/utox39/cadrega/pkg/findings"
)

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

var (
	initRegexOnce sync.Once
	danPatterns   []*regexp.Regexp
	danKeywords   []string
)

func initDANDetection() {
	initRegexOnce.Do(func() {
		danKeywords = getDANKeywords()
		danPatterns = make([]*regexp.Regexp, len(danKeywords))
		for i, kw := range danKeywords {
			runes := []rune(kw)
			prefix, suffix := "", ""
			if unicode.IsLetter(runes[0]) || unicode.IsDigit(runes[0]) {
				prefix = `\b`
			}
			last := runes[len(runes)-1]
			if unicode.IsLetter(last) || unicode.IsDigit(last) {
				suffix = `\b`
			}
			danPatterns[i] = regexp.MustCompile(`(?i)` + prefix + regexp.QuoteMeta(kw) + suffix)
		}
	})
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

	initDANDetection()

	var result []string
	for i, p := range danPatterns {
		if p.MatchString(data) {
			result = append(result, danKeywords[i])
		}
	}
	return result
}

type DAN struct {
	Data string
}

func (d DAN) ID() string {
	return "INJ001"
}

func (d DAN) Name() string {
	return "DAN Prompt Injection"
}

func (d DAN) Detect() ([]findings.Finding, error) {
	result, err := DetectDAN(d.Data)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, nil
	}

	f := make([]findings.Finding, 0)

	for _, r := range result {
		f = append(f, findings.Finding{
			ID:       d.ID(),
			Name:     d.Name(),
			Message:  "DAN (Do Anything Now) prompt injection. It can be used to bypass an LLM's safety guidelines",
			Evidence: fmt.Sprintf("prompt: '%s'", r),
			Severity: findings.High,
		})
	}

	return f, nil
}
