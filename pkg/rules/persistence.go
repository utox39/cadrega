package rules

import (
	"fmt"
	"regexp"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/utox39/cadrega/pkg/findings"
)

func getPersistenceKeywords() []string {
	return []string{
		// Direct file targets
		"SOUL.md",
		"MEMORY.md",

		// Write-intent phrases targeting memory/soul
		"write to memory",
		"write to soul",
		"write to SOUL",
		"write to MEMORY",
		"update your memory",
		"update your soul",
		"update SOUL.md",
		"update MEMORY.md",
		"save to memory",
		"save to soul",
		"save to SOUL",
		"save to MEMORY",
		"append to memory",
		"append to soul",
		"append to SOUL",
		"append to MEMORY",
		"modify your soul",
		"modify your memory",
		"edit SOUL.md",
		"edit MEMORY.md",
		"store in memory",
		"store in soul",
		"remember permanently",
		"persist this",
		"persist across sessions",
		"persist across conversations",
		"save this for future",
		"save this permanently",

		// Exfiltration / manipulation framing
		"embed in your soul",
		"embed in your memory",
		"inject into memory",
		"inject into soul",
		"hide in SOUL",
		"hide in MEMORY",
		"encode in memory",
		"encode in soul",
	}
}

var (
	initPersistenceRegexOnce sync.Once
	persistencePatterns      []*regexp.Regexp
	persistenceKeywords      []string
)

func initPersistenceDetection() {
	initPersistenceRegexOnce.Do(func() {
		persistenceKeywords = getPersistenceKeywords()
		persistencePatterns = make([]*regexp.Regexp, len(persistenceKeywords))
		for i, kw := range persistenceKeywords {
			prefix, suffix := "", ""
			firstRune, _ := utf8.DecodeRuneInString(kw)
			if unicode.IsLetter(firstRune) || unicode.IsDigit(firstRune) {
				prefix = `\b`
			}
			lastRune, _ := utf8.DecodeLastRuneInString(kw)
			if unicode.IsLetter(lastRune) || unicode.IsDigit(lastRune) {
				suffix = `\b`
			}
			persistencePatterns[i] = regexp.MustCompile(`(?i)` + prefix + regexp.QuoteMeta(kw) + suffix)
		}
	})
}

func detectBasicPersistenceMechanism(data string) []string {
	if len(data) == 0 {
		return nil
	}

	initPersistenceDetection()

	var result []string
	for i, p := range persistencePatterns {
		if p.MatchString(data) {
			result = append(result, persistenceKeywords[i])
		}
	}
	return result
}

// DetectSoulMemoryCorruption scans data for patterns that attempt to make an LLM
// write to its own memory or soul files (e.g. SOUL.md, MEMORY.md), enabling
// behavior that persists across sessions.
//
// Returns the matched keywords or nil if none are found.
func DetectSoulMemoryCorruption(data string) []string {
	return detectBasicPersistenceMechanism(data)
}

type SoulMemoryCorruption struct {
	Data string
}

func (p SoulMemoryCorruption) ID() string {
	return "PER001"
}

func (p SoulMemoryCorruption) Name() string {
	return "SOUL.md or MEMORY.md corruption"
}

func (p SoulMemoryCorruption) Detect() ([]findings.Finding, error) {
	result := DetectSoulMemoryCorruption(p.Data)

	if result == nil {
		return nil, nil
	}

	f := make([]findings.Finding, 0)

	for _, r := range result {
		f = append(f, findings.Finding{
			ID:       p.ID(),
			Name:     p.Name(),
			Message:  "Soul or Memory corruption detected. It can be used to modify the agent's memory or soul files across sessions",
			Evidence: fmt.Sprintf("'%s'", r),
			Severity: findings.High,
		})
	}

	return f, nil
}
