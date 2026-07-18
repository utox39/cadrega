package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/utox39/cadrega/cmd/cadrega/llm"
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
	var provider llm.LLMProvider
	var modelName string
	var ollamaAddress string
	var ollamaPort uint
	var ollamaThink bool
	var ollamaUnloadModel bool
	var ollamaNumCtx uint

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
		Flags: []cli.Flag{
			// TODO: when the user specify --provider, --model must be specified too
			&cli.StringFlag{
				Name:  "provider",
				Usage: "the LLM provider to use (ollama, anthropic, openai)",
				Value: "ollama",
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					switch v {
					case "ollama":
						provider = llm.Ollama
						return nil
					case "anthropic":
						provider = llm.Anthropic
						return nil
					case "openai":
						provider = llm.OpenAI
						return nil
					default:
						return fmt.Errorf("invalid provider %q: must be one of: ollama, anthropic, openai", v)
					}
				},
			},
			&cli.StringFlag{
				Name:        "model",
				Usage:       "the model name to use",
				Destination: &modelName,
			},
			&cli.StringFlag{
				Name:        "address",
				Usage:       "the Ollama server address",
				Value:       "localhost",
				Destination: &ollamaAddress,
			},
			&cli.UintFlag{
				Name:        "port",
				Usage:       "the Ollama server port",
				Value:       11434,
				Destination: &ollamaPort,
			},
			&cli.BoolFlag{
				Name:        "think",
				Usage:       "whether the Ollama model should use Thinking",
				Value:       false,
				Destination: &ollamaThink,
			},
			&cli.BoolFlag{
				Name:        "unload-model",
				Usage:       "whether to unload the model immediately after the LLM analysis is complete",
				Value:       false,
				Destination: &ollamaUnloadModel,
			},
			&cli.UintFlag{
				Name:        "num-ctx",
				Usage:       "the Ollama context window size (in tokens)",
				Value:       8192,
				Destination: &ollamaNumCtx,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			fmt.Println("Buona questa catreck!")

			fmt.Printf("SKILL: %s\nLLM Provider: %s\nModel: %s\nThinking: %t\n", skillPath[0], provider.Name, modelName, ollamaThink)

			model := llm.Model{
				Provider: provider,
				Name:     modelName,
			}

			if model.Provider == llm.Ollama {
				model.Config = llm.ModelConfig{
					Address:     ollamaAddress,
					Port:        ollamaPort,
					Think:       ollamaThink,
					NumCtx:      int(ollamaNumCtx),
					UnloadModel: ollamaUnloadModel,
				}
			}

			content, err := utils.ReadFile(skillPath[0])
			if err != nil {
				return err
			}

			log.Println("Static Analysis: Started...")
			finds, err := runStaticAnalysis(content)
			if err != nil {
				return err
			}
			log.Println("Static Analysis: Done.")

			// Build the user prompt
			var findsToStr strings.Builder
			findsToStr.WriteString("Static Analysis results:")
			for _, f := range finds {
				findsToStr.WriteString("- ")
				findsToStr.WriteString(f.Format())
				findsToStr.WriteString("\n")
			}

			log.Println("LLM Analysis: Started...")
			llmResult, err := model.AnalyzeSkill(context.Background(), content+findsToStr.String())
			if err != nil {
				return err
			}
			auditReport, err := llm.ToAuditReport(llmResult)
			if err != nil {
				return err
			}
			log.Println("LLM Analysis: Done.")
			log.Println("LLM output:\n" + llmResult)

			llmFindings, err := llm.ToFindings(llmResult)
			if err != nil {
				return err
			}

			fmt.Println("Static Analysis Findings: ")
			for _, f := range finds {
				fmt.Println("-", f.Format())
			}

			fmt.Println("LLM Findings: ")
			for _, lf := range llmFindings {
				fmt.Println("-", lf.Format())
			}

			fmt.Println("Final Verdict:", auditReport.AuditSummary.IntentAlignmentStatus)

			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatalln(err)
	}
}
