package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/utox39/cadrega/cmd/cadrega/llm"
	"github.com/utox39/cadrega/cmd/cadrega/results"
	"github.com/utox39/cadrega/cmd/cadrega/server"
	"github.com/utox39/cadrega/cmd/cadrega/staticanalysis"
	"github.com/utox39/cadrega/cmd/cadrega/tui"
	"github.com/utox39/cadrega/cmd/cadrega/utils"
)

// verbose is declared at the root command, so it applies to every subcommand.
var verbose bool

// scanOptions holds the flags and arguments of the `scan` subcommand.
type scanOptions struct {
	skillPath         []string
	provider          llm.LLMProvider
	modelName         string
	ollamaAddress     string
	ollamaPort        uint
	ollamaThink       bool
	ollamaUnloadModel bool
	ollamaNumCtx      uint
	jsonOutput        bool
	tuiOutput         bool
}

// serveOptions holds the flags of the `serve` subcommand.
type serveOptions struct {
	address string
	port    uint
}

// newScanCommand returns the `scan` subcommand, which analyzes a single skill
// from the command line. It owns the mandatory `skillpath` argument and the
// mandatory `--provider` / `--model` flags: they live here instead of on the
// root command because urfave/cli checks required flags along the whole parent
// chain, which would force `serve` to provide them too.
func newScanCommand() *cli.Command {
	var opts scanOptions

	return &cli.Command{
		Name:      "scan",
		Usage:     "analyze a skill",
		ArgsUsage: "<skillpath>",
		Arguments: []cli.Argument{
			&cli.StringArgs{
				Name:        "skillpath",
				Destination: &opts.skillPath,
				UsageText:   "The skill path",
				Min:         1,
				Max:         1,
				Config: cli.StringConfig{
					TrimSpace: true,
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "provider",
				Usage:    "the LLM provider to use (ollama, anthropic, openai)",
				Required: true,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					provider, err := llm.ParseLLMProvider(v)
					if err != nil {
						return err
					}
					opts.provider = provider
					return nil
				},
			},
			&cli.StringFlag{
				Name:        "model",
				Usage:       "the model name to use",
				Required:    true,
				Destination: &opts.modelName,
			},
			&cli.StringFlag{
				Name:        "address",
				Usage:       "the Ollama server address",
				Value:       "localhost",
				Destination: &opts.ollamaAddress,
			},
			&cli.UintFlag{
				Name:        "port",
				Usage:       "the Ollama server port",
				Value:       11434,
				Destination: &opts.ollamaPort,
			},
			&cli.BoolFlag{
				Name:        "think",
				Usage:       "whether the Ollama model should use Thinking",
				Value:       false,
				Destination: &opts.ollamaThink,
			},
			&cli.BoolFlag{
				Name:        "unload-model",
				Usage:       "whether to unload the model immediately after the LLM analysis is complete",
				Value:       false,
				Destination: &opts.ollamaUnloadModel,
			},
			&cli.UintFlag{
				Name:        "num-ctx",
				Usage:       "the Ollama context window size (in tokens)",
				Value:       8192,
				Destination: &opts.ollamaNumCtx,
			},
			&cli.BoolFlag{
				Name:        "json",
				Usage:       "get JSON output",
				Value:       false,
				Destination: &opts.jsonOutput,
			},
			&cli.BoolFlag{
				Name:        "tui",
				Usage:       "show results in an interactive TUI",
				Value:       false,
				Destination: &opts.tuiOutput,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if opts.jsonOutput && opts.tuiOutput {
				return fmt.Errorf("--tui and --json cannot be used together")
			}

			if !opts.jsonOutput {
				fmt.Println("Buona questa catreck!")
				fmt.Printf("- SKILL: %s\n- LLM Provider: %s\n- Model: %s\n- Thinking: %t\n", opts.skillPath[0], opts.provider.Name, opts.modelName, opts.ollamaThink)
			}

			return runScan(ctx, opts)
		},
	}
}

func runScan(ctx context.Context, opts scanOptions) error {
	model := llm.Model{
		Provider: opts.provider,
		Name:     opts.modelName,
	}

	if model.Provider == llm.Ollama {
		model.Config = llm.ModelConfig{
			Address:     opts.ollamaAddress,
			Port:        opts.ollamaPort,
			Think:       opts.ollamaThink,
			NumCtx:      int(opts.ollamaNumCtx),
			UnloadModel: opts.ollamaUnloadModel,
		}
	}

	content, err := utils.ReadFile(opts.skillPath[0])
	if err != nil {
		return err
	}

	log.Println("Static Analysis: Started...")
	staticFindings, staticErr := staticanalysis.RunStaticAnalysis(content)
	if staticErr != nil {
		// In order to perform the LLM analysis, any errors from the static analysis
		// are logged and the analysis continues with the partial findings generated
		// by the static analysis.
		fmt.Fprintf(os.Stderr, "static analysis: %v (continuing with partial results)\n", staticErr)
	}
	log.Println("Static Analysis: Done.")

	// Build the user prompt
	var findsToStr strings.Builder
	findsToStr.WriteString("Static Analysis results:")
	for _, f := range staticFindings {
		findsToStr.WriteString("- ")
		findsToStr.WriteString(f.Format())
		findsToStr.WriteString("\n")
	}

	log.Println("LLM Analysis: Started...")
	llmResult, err := model.AnalyzeSkill(ctx, content+findsToStr.String())
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

	// TODO: That's a naive solution. A score-based verdict could be a better solution
	staticAnalysisVerdict := results.Malicious
	switch {
	case staticErr != nil:
		staticAnalysisVerdict = results.Unknown
	case len(staticFindings) == 0:
		staticAnalysisVerdict = results.Safe
	}

	switch {
	case opts.tuiOutput:
		return tui.RunTUI(tui.TuiData{
			StaticFindings: staticFindings,
			LLMFindings:    llmFindings,
			StaticVerdict:  staticAnalysisVerdict.Name,
			LLMVerdict:     auditReport.AuditSummary.IntentAlignmentStatus,
			LLMOutput:      llmResult,
			Verbose:        verbose,
		})
	case opts.jsonOutput:
		rj := results.ResultsJSON{
			StaticFindings: staticFindings,
			LLMFindings:    llmFindings,
			StaticVerdict:  staticAnalysisVerdict,
			LLMVerdict:     results.Verdict{Name: auditReport.AuditSummary.IntentAlignmentStatus},
		}
		vj, err := rj.FormatAsJSON()
		if err != nil {
			return err
		}

		fmt.Println(vj)
	default:
		fmt.Println("Static Analysis Findings: ")
		for _, f := range staticFindings {
			fmt.Println("-", f.Format())
		}

		fmt.Println("LLM Findings: ")
		for _, lf := range llmFindings {
			fmt.Println("-", lf.Format())
		}

		fmt.Printf("- Final Verdict:\n> Static Analysis: %s\n> LLM Analysis: %s\n", staticAnalysisVerdict.Name, auditReport.AuditSummary.IntentAlignmentStatus)
	}

	return nil
}

// newServeCommand returns the `serve` subcommand, which runs cadrega as an HTTP
// service. The skill to analyze and the LLM provider/model are supplied per
// request, so none of the `scan` flags are required here.
func newServeCommand() *cli.Command {
	var opts serveOptions

	return &cli.Command{
		Name:  "serve",
		Usage: "run cadrega as an HTTP service",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "address",
				Usage:       "the address the HTTP server listens on",
				Value:       "localhost",
				Destination: &opts.address,
			},
			&cli.UintFlag{
				Name:        "port",
				Usage:       "the port the HTTP server listens on",
				Value:       8080,
				Destination: &opts.port,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runServe(opts)
		},
	}
}

func runServe(opts serveOptions) error {
	mux := http.NewServeMux()
	mux.Handle("GET /", server.StaticHandler())
	mux.HandleFunc("POST /analyze", server.Analyze)
	fmt.Printf("Cadrega server is listening on: %s:%d\n", opts.address, opts.port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", opts.address, opts.port), server.SecurityHeaders(mux)); err != nil {
		return err
	}
	return nil
}

func main() {
	cmd := &cli.Command{
		Name:    "cadrega",
		Usage:   "Malicious Skills Detector",
		Version: "0.1.0",
		// `scan` runs when the first positional argument is not a subcommand
		// name, so `cadrega <skillpath>` keeps working.
		DefaultCommand: "scan",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "verbose",
				Usage:       "get verbose output",
				Value:       false,
				Destination: &verbose,
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			// By default, the log output is discarded.
			// The default value of the `verbose` flag is false.
			// If the user uses the `verbose` flag, the logger's output is written to stderr (by default).
			if !verbose {
				log.SetOutput(io.Discard)
			}
			return ctx, nil
		},
		Commands: []*cli.Command{
			newScanCommand(),
			newServeCommand(),
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		// Written straight to stderr rather than through `log`, whose output is
		// discarded unless `--verbose` is set.
		fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[0], err)
		os.Exit(1)
	}
}
