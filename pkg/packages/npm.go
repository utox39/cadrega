// Package packages implements functions to:
// - detect npm package typosquatting
package packages

import (
	"fmt"

	"github.com/hbollon/go-edlib"

	"github.com/utox39/cadrega/pkg/findings"
)

// DetectNpmPackageTyposquatting detects npm package typosquatting attacks by
// comparing a package name against a list of known legitimate packages.
// Typosquatting exploits users making simple typing mistakes (e.g., "lodahs"
// instead of "lodash") to trick them into installing malicious packages.
//
// Similarity is calculated using the Damerau-Levenshtein distance metric,
// normalized to a value between 0.0 (completely different) and 1.0 (identical).
// A package is flagged as a typosquat if its similarity to any legitimate
// package is >= threshold.
//
// Suggested threshold: 0.8 (80% similarity) balances detection coverage with
// false positive rate.
//
// Returns a slice of findings for packages exceeding the threshold, or an empty
// slice if none are found.
func DetectNpmPackageTyposquatting(pkg string, typosquats []string, threshold float32) ([]findings.Finding, error) {
	f := make([]findings.Finding, 0)

	for _, t := range typosquats {
		distance, err := edlib.StringsSimilarity(pkg, t, edlib.DamerauLevenshtein)
		if err != nil {
			return nil, err
		}

		if distance >= threshold {
			f = append(f, findings.Finding{
				Name:     "Package Typosquating",
				Severity: findings.High,
				Message:  fmt.Sprintf("The package '%s' could be a typosquat of the package '%s'", pkg, t),
				Evidence: fmt.Sprintf("The DamerauLevenshtein distance between '%s' and '%s' is: %.3f", pkg, t, distance),
			})
		}
	}

	return f, nil
}
