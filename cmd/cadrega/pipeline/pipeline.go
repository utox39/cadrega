// Package pipeline provides the analysis pipeline that runs security rules concurrently.
package pipeline

import (
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/utox39/cadrega/pkg/findings"
	"github.com/utox39/cadrega/pkg/rules"
)

// Pipeline represents the analysis pipeline. It holds a set of rules that are
// executed concurrently when Run is called.
type Pipeline struct {
	Rules []rules.Rule
}

// NewPipeline creates and returns a new Pipeline initialized with the given rules.
func NewPipeline(rules []rules.Rule) *Pipeline {
	return &Pipeline{
		Rules: rules,
	}
}

// Run executes all rules concurrently and sends each rule's findings to f.
// It returns the first non-nil error encountered by any rule, if any.
func (p *Pipeline) Run(f chan<- []findings.Finding) error {
	var eg errgroup.Group

	for _, r := range p.Rules {
		eg.Go(func() error {
			results, err := r.Detect()
			if err != nil {
				return fmt.Errorf("%s error: %v", r.Name(), err)
			}

			f <- results
			return nil
		})
	}

	return eg.Wait()
}
