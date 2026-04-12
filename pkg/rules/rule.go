package rules

import "github.com/utox39/cadrega/pkg/findings"

type Rule interface {
	ID() string
	Name() string
	Detect() ([]findings.Finding, error)
}
