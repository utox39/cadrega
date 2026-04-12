// Package findings provides types and utilities for representing security
// findings produced by cadrega's analysis rules.
//
// A Finding captures a detected issue with its name, severity, a human-readable
// message, and the evidence that triggered it. Severity levels range from Low
// to High
package findings

import "fmt"

type Severity int

const (
	Low Severity = iota
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// Finding represents a single security issue detected during analysis.
//
//   - ID:       unique rule identifier (e.g. "ENC001")
//   - Name:     short human-readable name of the rule that produced the finding
//   - Message:  description of the issue and its potential impact
//   - Evidence: the raw input that triggered the finding, including decoded form where applicable
//   - Severity: impact level — Low, Medium, or High
type Finding struct {
	ID       string
	Name     string
	Message  string
	Evidence string
	Severity Severity
}

func (f Finding) Format() string {
	return fmt.Sprintf("[%s]  %s\n\tMessage:  %s\n\tEvidence: %s", f.Severity, f.Name, f.Message, f.Evidence)
}
