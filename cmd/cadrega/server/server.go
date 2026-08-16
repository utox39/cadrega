// Package server implements the HTTP service exposed by `cadrega serve`: the
// embedded single-page web UI, the /analyze endpoint it submits to, and the
// security headers (CSP, X-Content-Type-Options) applied to every response.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/utox39/cadrega/cmd/cadrega/llm"
	"github.com/utox39/cadrega/cmd/cadrega/results"
	"github.com/utox39/cadrega/cmd/cadrega/staticanalysis"
)

// maxRequestBodySize bounds how many bytes Analyze will read from a request
// body. It must stay ahead of the web UI's client-side file-size check
// (cmd/cadrega/server/static/app.js: MAX_FILE_SIZE, 5 MiB) to cover the
// AnalyzeRequest JSON envelope plus string-escaping overhead around
// skill_content, while still capping worst-case memory use for any client
// that skips the client-side check entirely (curl, a script, etc.).
const maxRequestBodySize = 8 * 1024 * 1024 // 8 MiB

//go:embed static
var staticFiles embed.FS

// StaticHandler serves the single-page web UI (index.html, app.css, app.js)
// used to submit skills to /analyze.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		// staticFiles is embedded at build time from a directory that is known
		// to exist, so Sub can only fail here on a build-time regression.
		panic(err)
	}
	return http.FileServerFS(sub)
}

// contentSecurityPolicy mirrors the <meta> CSP in static/index.html, plus
// frame-ancestors, which browsers ignore in a <meta> tag and only honor as a
// real response header. The <meta> tag is kept too as a defense-in-depth
// fallback for that page specifically; this header is the one actually
// enforced everywhere, including non-HTML responses like /analyze's errors.
const contentSecurityPolicy = "default-src 'none'; connect-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// SecurityHeaders wraps a handler to set response headers that apply to
// every route, not just the HTML page: CSP (with frame-ancestors, for
// clickjacking protection) and X-Content-Type-Options (to stop browsers from
// MIME-sniffing error/JSON responses into something executable).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

type AnalyzeRequest struct {
	Provider          llm.LLMProvider `json:"provider"`
	ModelName         string          `json:"model_name"`
	OllamaAddress     string          `json:"ollama_address,omitempty"`
	OllamaPort        uint            `json:"ollama_port,omitempty"`
	OllamaThink       bool            `json:"ollama_think,omitempty"`
	OllamaUnloadModel bool            `json:"ollama_unload_model,omitempty"`
	OllamaNumCtx      uint            `json:"ollama_num_ctx,omitempty"`
	SkillContent      string          `json:"skill_content"`
}

func Analyze(w http.ResponseWriter, r *http.Request) {
	var errDescription string

	// Sanity check
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		errDescription = "Wrong Content-Type:" + contentType
		log.Println(errDescription)
		http.Error(w, errDescription, http.StatusBadRequest)
		return
	}

	// Initialized with the default values for the optional fields.
	analyzeRequest := AnalyzeRequest{
		OllamaAddress:     "localhost",
		OllamaPort:        11434,
		OllamaThink:       false,
		OllamaUnloadModel: false,
		OllamaNumCtx:      8192,
	}

	// MaxBytesReader aborts the read (and Decode below) as soon as the body
	// exceeds the limit, instead of letting Decode buffer an arbitrarily
	// large body into memory before any size check runs.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	if err := json.NewDecoder(r.Body).Decode(&analyzeRequest); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			errDescription = fmt.Sprintf("Request body too large: max %d bytes", maxRequestBodySize)
			log.Println(errDescription)
			http.Error(w, errDescription, http.StatusRequestEntityTooLarge)
			return
		}

		errDescription = fmt.Sprintf("Invalid AnalyzeRequest: %v", err)
		log.Println(errDescription)
		http.Error(w, errDescription, http.StatusBadRequest)
		return
	}

	log.Println("Static Analysis: Started...")
	staticFindings, staticErr := staticanalysis.RunStaticAnalysis(analyzeRequest.SkillContent)
	if staticErr != nil {
		// In order to perform the LLM analysis, any errors from the static analysis
		// are logged and the analysis continues with the partial findings generated
		// by the static analysis.
		fmt.Fprintf(os.Stderr, "static analysis: %v (continuing with partial results)\n", staticErr)
	}
	log.Println("Static Analysis: Done.")

	model := llm.Model{
		Provider: analyzeRequest.Provider,
		Name:     analyzeRequest.ModelName,
	}

	if model.Provider == llm.Ollama {
		model.Config = llm.ModelConfig{
			Address:     analyzeRequest.OllamaAddress,
			Port:        analyzeRequest.OllamaPort,
			Think:       analyzeRequest.OllamaThink,
			NumCtx:      int(analyzeRequest.OllamaNumCtx),
			UnloadModel: analyzeRequest.OllamaUnloadModel,
		}
	}

	// Build the user prompt
	var findsToStr strings.Builder
	findsToStr.WriteString("Static Analysis results:")
	for _, f := range staticFindings {
		findsToStr.WriteString("- ")
		findsToStr.WriteString(f.Format())
		findsToStr.WriteString("\n")
	}

	log.Println("LLM Analysis: Started...")
	llmResult, err := model.AnalyzeSkill(context.Background(), analyzeRequest.SkillContent+findsToStr.String())
	if err != nil {
		errDescription = fmt.Sprintf("LLM error: %v", err)
		log.Println(errDescription)
		http.Error(w, errDescription, http.StatusInternalServerError)
		return
	}
	log.Println("LLM Analysis: Done.")
	log.Println("LLM output:\n" + llmResult)

	auditReport, err := llm.ToAuditReport(llmResult)
	if err != nil {
		errDescription = fmt.Sprintf("Failed to generate the LLM Audit Report: %v\nLLM Output: %s", err, llmResult)
		log.Println(llmResult)
		log.Println(errDescription)
		http.Error(w, errDescription, http.StatusInternalServerError)
		return
	}

	llmFindings, err := llm.ToFindings(llmResult)
	if err != nil {
		errDescription = fmt.Sprintf("Failed to generate the LLM findings: %v\nLLM Output: %s", err, llmResult)
		log.Println(errDescription)
		http.Error(w, errDescription, http.StatusInternalServerError)
		return
	}

	// TODO: That's a naive solution. A score-based verdict could be a better solution
	staticAnalysisVerdict := results.Malicious
	switch {
	case staticErr != nil:
		staticAnalysisVerdict = results.Unknown
	case len(staticFindings) == 0:
		staticAnalysisVerdict = results.Safe
	}

	rj := results.ResultsJSON{
		StaticFindings: staticFindings,
		LLMFindings:    llmFindings,
		StaticVerdict:  staticAnalysisVerdict,
		LLMVerdict:     results.Verdict{Name: auditReport.AuditSummary.IntentAlignmentStatus},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(rj); err != nil {
		errDescription = fmt.Sprintf("Failed to encode the results: %v", err)
		log.Println(errDescription)
		http.Error(w, errDescription, http.StatusInternalServerError)
	}
}
