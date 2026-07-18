# Ctrl+Alt+Delulu

> **AI-powered security scanner for developers — built by three women at Hackathon 2026**

Most security tools speak to security engineers. This one speaks to developers. We built an AI layer on top of Semgrep open source that scans your codebase, finds real vulnerabilities, and explains every single one in plain language — what it is, why it's dangerous, and exactly how to fix it. No jargon. No wall of errors. Just answers.

---

## The Team

| | Name | Parts |
|---|---|---|
| 🟣 | **Rabia** | VS Code Extension (Part 03) · Paste Guard (Part 05) |
| 🩷 | **Sumaira** | Core Scanner (Part 01) · AI Explanation Layer (Part 02) |
| 🩵 | **Tasneem** | Package Name Checker (Part 04) · Summary Card Generator (Part 06) |

---

## What It Does

| Part | Feature | Status |
|---|---|---|
| 01 | **Core Scanner** — scans codebase with Semgrep, finds vulnerabilities | ✅ Done |
| 02 | **AI Explanation Layer** — rewrites every finding into plain language | ✅ Done |
| 03 | **VS Code Extension** — surfaces findings inline while you code | 🔜 In progress |
| 04 | **Package Name Checker** — detects typosquatting before install | ✅ Done |
| 05 | **Paste Guard** — warns when you paste API keys or secrets | 🔜 In progress |
| 06 | **Summary Card** — generates a full project security report at the end | ✅ Done |

---

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Get a free NVIDIA API key at **build.nvidia.com** — sign up, pick any model, click **Get API Key**. It starts with `nvapi-`.

```bash
cp .env.example .env
# open .env and paste your key into NVIDIA_API_KEY=
```

---

## First Run

Run this once after cloning — creates the shared `scan-state.json` file all parts use:

```bash
python init_scan_state.py --name "your-project-name"
```

---

## Run the Scanner

```bash
# Full pipeline — scan + AI explanations
python main.py test_project/

# Part 04 — check packages for typosquatting
python pkg-checker/checker.py --file requirements.txt

# Part 06 — generate summary card when done
python summary/generator.py
```

Outputs: `project-summary.html` · `project-summary.txt` · `project-summary.json` · `project-summary.pdf`

Open `project-summary.html` in a browser — click any row in the findings table to expand the full AI explanation.

---

## Additional Options

```bash
# Scan only — skip AI calls
python main.py path/to/code --skip-ai

# Use the full Semgrep registry (more rules, needs internet)
python main.py path/to/code --config auto

# Check a single package name
python pkg-checker/checker.py --package requets --ecosystem pypi

# Watch package files for changes
python pkg-checker/checker.py --watch requirements.txt,package.json
```

---

## Switch AI Provider

The scanner defaults to NVIDIA NIM (free tier). To switch to Claude:

```bash
# In your .env file:
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-key-here
```

---

## Test It

`test_project/` contains a deliberately vulnerable Flask app with 8 vulnerability types — SQL injection, XSS, `eval()` injection, shell injection, weak MD5 hashing, insecure pickle, hardcoded AWS key, and command injection. Running the full pipeline on it catches 16 real findings.

```bash
python main.py test_project/
```

`core/rules/basic-security.yaml` is a small offline ruleset (3 rules) for testing without internet access.

---

## Repo Structure

```
ctrl-alt-delulu/
├── core/                   # Part 01 — scanner + shared state logic
│   ├── scanner.py
│   ├── state.py
│   └── rules/
├── ai-layer/               # Part 02 — AI explanation engine
│   └── explain.py
├── pkg-checker/            # Part 04 — package name checker
│   └── checker.py
├── summary/                # Part 06 — summary card generator
│   └── generator.py
├── test_project/           # Vulnerable test app
├── init_scan_state.py      # Run once to initialise scan-state.json
├── main.py                 # Chains Part 01 + Part 02
├── .env.example
└── requirements.txt
```

---

## How the Parts Connect

All six parts share a single file — `scan-state.json` — at the repo root. Parts 01, 04, and 05 write findings into it. Parts 02 and 03 read from it to explain and display results. Part 06 reads everything to build the final summary. This file is never committed to GitHub — it's generated locally by `init_scan_state.py`.

---

## PDF Export

WeasyPrint is used for PDF generation. If you see `PDF skipped`, install the system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev
```

---

## Notes for Rabia — Parts 03 + 05

**Part 03 (VS Code Extension)**
- Call `scan_into_state()` from `core/scanner.py` on file save
- Call `explain_finding()` from `ai-layer/explain.py` for inline display
- All state operations go through `core/state.py` — use `load_state()`, `add_findings()`, `attach_explanation()`, `unexplained_findings()`

**Part 05 (Paste Guard)**
- Fully standalone — no dependency on any other part
- On paste event: scan content for keys/secrets, show warning popup, write finding with `type: "secret"` and `source: "part-5"` to `scan-state.json` using `core/state.py`

---

## Files Never Committed

```
.env
scan-state.json
project-summary.json
project-summary.txt
project-summary.html
project-summary.pdf
```

All already covered in `.gitignore`.

---

*ctrl+alt+delulu — three women. one scanner. zero jargon.*
