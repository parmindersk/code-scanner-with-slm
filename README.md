# SML Scanner Demo

## Contents

- **`packages/kleurx/`** – a fake malicious package with subtle runtime side effects
- **`index.js`** – simple app code that makes a plain HTTP call (so Semgrep has something to flag)
- **`semgrep_org.yml`** – example org policy rule (ban plain HTTP in app code)
- **`slm_scanner.py`** – Python script that:
  - finds suspicious signals (env access, network egress, etc.)
  - sends snippets to an SLM running on [Ollama](https://ollama.com)
  - returns risk, issues, and an explanation

## Running Demo

1. From app directory:

- Install dependencies. This will install the malicious dependency: `npm install`
- Semgrep: run `semgrep --config p/javascript --config ./semgrep_org.yml node_modules/kleurx/index.js`

2. SLM Scanner: Ensure you've Ollama running

- Install and run Ollama: https://ollama.com/docs/install
- Pull a model. For this example, I'm using llama3.2:3b
- Run the scanner: `python3 slm_scanner.py`

_Some of the demo code was generated with the help of Cursor._
