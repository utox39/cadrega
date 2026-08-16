// Package results provides the combined static-analysis/LLM verdict and
// findings types used for cadrega's output, and helpers to format them as
// JSON.
package results

import (
	"encoding/json"

	"github.com/utox39/cadrega/pkg/findings"
)

type Verdict struct{ Name string }

var (
	Safe       = Verdict{"SAFE"}
	Suspicious = Verdict{"SUSPICIOUS"}
	Malicious  = Verdict{"MALICIOUS"}
	Unknown    = Verdict{"UNKNOWN"}
)

func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.Name)
}

type ResultsJSON struct {
	StaticFindings []findings.Finding `json:"staticFindings"`
	LLMFindings    []findings.Finding `json:"llmFindings"`
	StaticVerdict  Verdict            `json:"staticVerdict"`
	LLMVerdict     Verdict            `json:"llmVerdict"`
}

func (rj ResultsJSON) FormatAsJSON() (string, error) {
	jsonOutput, err := json.Marshal(rj)
	if err != nil {
		return "", err
	}

	return string(jsonOutput), nil
}
