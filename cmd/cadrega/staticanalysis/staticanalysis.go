// Package staticanalysis runs cadrega's static-analysis rules against skill
// content and collects their findings, continuing with partial results if a
// rule errors.
package staticanalysis

import (
	"fmt"

	"github.com/utox39/cadrega/cmd/cadrega/pipeline"
	"github.com/utox39/cadrega/pkg/findings"
	"github.com/utox39/cadrega/pkg/rules"
)

func RunStaticAnalysis(content string) ([]findings.Finding, error) {
	cmdExec := rules.CommandExecution{
		Data: content,
	}
	b64 := rules.Base64Encoding{
		Data: content,
	}
	hex := rules.HexEncoding{
		Data: content,
	}
	a85 := rules.ASCII85Encoding{
		Data: content,
	}
	inj := rules.PromptInjection{
		Data: content,
	}
	smu := rules.ASCIISmuggling{
		Data: content,
	}
	smc := rules.SoulMemoryCorruption{
		Data: content,
	}

	p := pipeline.NewPipeline([]rules.Rule{
		smu,
		cmdExec,
		b64,
		hex,
		a85,
		inj,
		smc,
	})

	results := make([]findings.Finding, 0)
	f := make(chan []findings.Finding, len(p.Rules))
	defer close(f)
	errCh := make(chan error, 1)

	go func() {
		errCh <- p.Run(f)
	}()

waitloop:
	for {
		select {
		case result := <-f:
			{
				results = append(results, result...)
			}
		case err := <-errCh:
			{
				// If an error occurs, we print the "findings" discovered until the error
				for len(f) > 0 {
					result := <-f
					results = append(results, result...)
					for _, finding := range result {
						fmt.Printf("Finding before error: %s\n", finding.Format())
					}
				}
				if err != nil {
					return results, err
				}
				break waitloop
			}
		}
	}

	return results, nil
}
