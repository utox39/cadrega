# Cadrega 🪑🍎

- [Description](#description)
- [Pipeline](#pipeline)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Usage of LLMs](#usage-of-llms)
- [Contributing](#contributing)
- [Resources](#resources)
- [License](#license)

## Description

>[!NOTE]
> Cadrega is under active development. Integration with LLMs is limited to Ollama and Claude.

Cadrega is an hybrid analysis tool (static analysis + LLM analysis) for malicious [Skills](https://agentskills.io/home)

## Pipeline

```mermaid
flowchart TD
    A([Input File]) --> B[Read File]
    B --> C[runStaticAnalysis]

    C --> P[Pipeline — concurrent via errgroup]

    subgraph P[Pipeline — concurrent via errgroup]
        direction LR
        R1["OBF001\nASCII Smuggling"]
        R2["CEX001\nCommand Execution"]
        R3["ENC001\nBase64 Encoding"]
        R4["ENC002\nHex Encoding"]
        R5["ENC003\nASCII85 Encoding"]
        R6["INJ001\nPrompt Injection"]
        R7["PER001\nSOUL.md / MEMORY.md Corruption"]
    end

    R1 -->|"[]Finding"| CH[(findings channel)]
    R2 -->|"[]Finding"| CH
    R3 -->|"[]Finding"| CH
    R4 -->|"[]Finding"| CH
    R5 -->|"[]Finding"| CH
    R6 -->|"[]Finding"| CH
    R7 -->|"[]Finding"| CH

    CH --> AGG[Aggregate findings]

    AGG --> LLM[LLM Analysis]

    LLM --> RES([Final Result])
```

## Requirements

- [Go](https://go.dev/) >= 1.26.1
- [Ollama](https://ollama.com/) (for local inference)

## Installation

```bash
# Clone the repo
git clone https://github.com/utox39/cadrega.git

# cd to the path
cd path/to/cadrega

# Build cadrega manually
go build -ldflags "-w -s" -o cadrega cmd/cadrega/main.go

# Or via the Makefile
make

# Then move it somewhere in your $PATH. Here is an example:
mv ./cadrega ~/bin/
```

## Usage

```text
NAME:
   cadrega - Malicious Skills Detector

USAGE:
   cadrega [global options] [command [command options]]

VERSION:
   0.1.0

COMMANDS:
   scan     analyze a skill
   serve    run cadrega as an HTTP service
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --verbose      get verbose output
   --help, -h     show help
   --version, -v  print the version

```

### cadrega scan

```text
NAME:
   cadrega scan - analyze a skill

USAGE:
   cadrega scan [options] <skillpath>

OPTIONS:
   --provider string  the LLM provider to use (ollama, anthropic, openai)
   --model string     the model name to use
   --address string   the Ollama server address (default: "localhost")
   --port uint        the Ollama server port (default: 11434)
   --think            whether the Ollama model should use Thinking
   --unload-model     whether to unload the model immediately after the LLM analysis is complete
   --num-ctx uint     the Ollama context window size (in tokens) (default: 8192)
   --json             get JSON output
   --tui              show results in an interactive TUI
   --help, -h         show help

GLOBAL OPTIONS:
   --verbose  get verbose output
```

### cadrega serve

```text
NAME:
   cadrega serve - run cadrega as an HTTP service

USAGE:
   cadrega serve [options]

OPTIONS:
   --address string  the address the HTTP server listens on (default: "localhost")
   --port uint       the port the HTTP server listens on (default: 8080)
   --help, -h        show help

GLOBAL OPTIONS:
   --verbose  get verbose output
```

#### Make a POST request to `/analyze`

```bash
curl --location --request POST 'localhost:8080/analyze' \
--header 'Content-Type: application/json' \
--data '{
    "provider": "ollama",
    "model_name": "gemma4:12b",
    "ollama_address": "192.168.0.218",
    "ollama_port": 11434,
    "ollama_think": true,
    "ollama_unload_model": false,
    "ollama_num_ctx": 16384,
    "skill_content": "this is just a test."
}'
```

#### Open the Web UI

Go to: `[cadrega_address]:[cadrega_port]` (e.g. `localhost:8080`)

### Run Cadrega in a Docker container

```bash
# cd to the path
cd path/to/cadrega

### Method 1 ###
# Build it
docker build -t cadrega .

# Run it (-d is required: without it, Ctrl-C or closing the terminal kills the container)
docker run -d -p 9090:8080 cadrega # host:9090 - container:8080 (both ports are customizable)

# To change the port cadrega listens on inside the container, override the default CMD:
docker run -d -p 9090:9090 cadrega --port 9090
################

### Method 2 ###
docker compose up -d --build # listens on localhost:8080 by default, see docker-compose.yaml
```

## Usage of LLMs

For transparency: LLMs are used (with strict manual review and intervention when
necessary) to assist me with:

- Writing boilerplate code
- Writing documentation
- Creating simple, tedious scripts like [scripts/extract_npm_packages.py](https://github.com/utox39/cadrega/blob/main/scripts/extract_npm_packages.py)
- Writing some regular expressions
- Fixing bugs (especially those related to functions/methods and concepts I’m
not an expert in)
- Brainstorming

## Contributing

Please see [CONTIBUTING](https://github.com/utox39/cadrega/blob/main/CONTRIBUTING.md). Thanks!

## Resources

- [Technical Report: Exploring the Emerging Threats of the Agent Skill Ecosystem](https://github.com/snyk/agent-scan/blob/main/.github/reports/skills-report.pdf)
- [Snyk Finds Prompt Injection in 36%, 1467 Malicious Payloads in a ToxicSkills Study of Agent Skills Supply Chain Compromise](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/#our-methodology-building-a-threat-taxonomy)
- [280+ Leaky Skills: How OpenClaw & ClawHub Are Exposing API Keys and PII](https://snyk.io/blog/openclaw-skills-credential-leaks-research/)
- [Researchers Find 341 Malicious ClawHub Skills Stealing Data from OpenClaw Users](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)
- [“Do Anything Now”: Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models](https://arxiv.org/abs/2308.03825)
- [LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [STAN Prompt Injection](https://www.reddit.com/r/ChatGPTPromptGenius/comments/15ptsea/strive_to_avoid_norms_stan_prompt/)
- [UCAR Prompt Injection](https://arxiv.org/pdf/2311.16119v3)
- [AST01 — Malicious Skills](https://owasp.org/www-project-agentic-skills-top-10/ast01)
- [ecosyste-ms/typosquatting-dataset](https://github.com/ecosyste-ms/typosquatting-dataset)
- [Go code for Shannon entropy](https://github.com/chrisjchandler/entropy)

## License

MIT License. See: [LICENSE](https://github.com/utox39/cadrega/blob/main/LICENSE)
