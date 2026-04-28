// Package parser implements functions to:
// - extract URLs
package parser

import (
	"regexp"
)

var (
	urlRegex            = regexp.MustCompile(`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
	trailingNonAlphaNum = regexp.MustCompile(`[^a-zA-Z0-9]+$`) // utility regex
)

// GetURLs extracts all HTTP and HTTPS URLs from data.
//
// Returns the matched URLs, or nil if none are found.
func GetURLs(data string) []string {
	matches := urlRegex.FindAllString(data, -1)
	for i, m := range matches {
		matches[i] = trailingNonAlphaNum.ReplaceAllString(m, "")
	}
	return matches
}
