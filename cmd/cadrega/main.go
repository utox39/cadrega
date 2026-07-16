package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/utox39/cadrega/cmd/cadrega/pipeline"
	"github.com/utox39/cadrega/cmd/cadrega/utils"
	"github.com/utox39/cadrega/pkg/findings"
	"github.com/utox39/cadrega/pkg/rules"
)

func runStaticAnalysis(content string) ([]findings.Finding, error) {
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
				for _, f := range result {
					fmt.Printf("%s\n", f.Format())
				}
			}
		case err := <-errCh:
			{
				for len(f) > 0 {
					result := <-f
					results = append(results, result...)
					for _, finding := range result {
						fmt.Printf("%s\n", finding.Format())
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

func main() {
	var skillPath []string

	cmd := &cli.Command{
		Name:      "cadrega",
		Usage:     "Malicious Skills Detector",
		ArgsUsage: "<skillpath>",
		Arguments: []cli.Argument{
			&cli.StringArgs{
				Name:        "skillpath",
				Destination: &skillPath,
				UsageText:   "The skill path",
				Min:         1,
				Max:         1,
				Config: cli.StringConfig{
					TrimSpace: true,
				},
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			fmt.Println("Buona questa catreck!")

			content, err := utils.ReadFile(skillPath[0])
			if err != nil {
				return err
			}

			_, err = runStaticAnalysis(content)
			if err != nil {
				return err
			}

			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatalln(err)
	}
}
