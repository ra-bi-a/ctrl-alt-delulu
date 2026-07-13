# Ctrl+Alt+Delulu

AI-powered vulnerability scanner. Scans code with Semgrep, explains findings in plain language with AI, checks for typosquatted packages, and generates a project summary card.

---

## ✅ Completed Parts

### Part 01 — Core Scanner
**Owner: Sumaira** · `core/scanner.py`, `core/state.py`, `core/rules/basic-security.yaml`

Wraps the Semgrep OSS CLI. Runs it on any file/folder, returns clean structured findings, writes them into the shared `scan-state.json`. Handles Semgrep's login-gated code-snippet quirk by reading snippets directly from disk. Deduplicates on re-scan — running it twice on unchanged code won't create duplicate findings.

### Part 02 — AI Explanation Layer
**Owner: Sumaira** · `ai-layer/explain.py`

Takes raw findings and calls an AI API to turn each into a plain-language explanation: what's wrong, why it matters, how to fix it. Defaults to **NVIDIA NIM (free)**, Anthropic/Claude supported as a drop-in alternate. Runs explanations in parallel, auto-retries on malformed AI JSON responses, skips findings that are already explained on re-run.

### Part 04 — Package Name Checker
**Owner: Tasneem** · `pkg-checker/checker.py`

Detects misspelled/typosquatted package names in `requirements.txt` (PyPI) and `package.json` (npm) using edit-distance matching against known trusted packages. Writes findings into `scan-state.json` in the same format as Part 01, so they're indistinguishable from core-scanner findings to every other part.

### Part 06 — Summary Card Generator
**Owner: Tasneem** · `summary/generator.py`

Triggered when development ends. Reads everything from `scan-state.json`, detects the project's tech stack, and outputs a full summary in three formats: JSON (machine-readable), TXT (plain text), HTML (styled card, click any finding row to expand full details — added by Sumaira). PDF export via WeasyPrint (see Known environment notes below).

**Shared infrastructure:** `init_scan_state.py` (Tasneem) creates the one shared `scan-state.json` file all parts read/write to. `main.py` (Sumaira) chains Part 01 → Part 02 together.

---

## ⏳ Not Started

| Part | Owner |
|---|---|
| 03 — VS Code Extension | Rabia |
| 05 — Paste Guard | Rabia |

---

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Get a free NVIDIA API key: **build.nvidia.com** → sign up → any model → **Get API Key** (starts with `nvapi-`).

```bash
cp .env.example .env
# paste your key into NVIDIA_API_KEY=...
```

---

## First-time setup (run once per clone)

```bash
python init_scan_state.py --name "ctrl-alt-delulu-scanner"
```
Creates `scan-state.json` — required before running any part.

---

## Run the full pipeline

```bash
python main.py test_project/          # Part 01 + 02: scan + explain
python pkg-checker/checker.py --file requirements.txt   # Part 04
python summary/generator.py                             # Part 06
```

Outputs: `project-summary.json` / `.txt` / `.html` / `.pdf`.
Open `project-summary.html` — click any row in **ALL FINDINGS** to expand full details.

### Run Part 01/02 only
```bash
python main.py path/to/codebase --config auto        # full Semgrep registry
python main.py path/to/codebase --skip-ai             # scan only, no AI calls
```

### Switch to Claude instead of NVIDIA
In `.env`:
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-key-here

---

## GitHub / Codespaces

Repo: `github.com/Sumera01/ctrl-alt-delulu`

**Codespaces:** repo page → **Code → Codespaces → Create codespace on main** → run Setup above.
**Local:** clone → open in VS Code → run Setup above → select `./venv` as interpreter.

**Never commit `.env`** — already gitignored. Only `.env.example` is tracked.

---

## What's gitignored (regenerated locally, never committed)
- `scan-state.json`
- `findings.json`, `explanations.json`
- `project-summary.json` / `.txt` / `.html` / `.pdf`

---

## Test target

`test_project/` — vulnerable Flask app, 8 vulnerability types (SQL injection, XSS, `eval()` injection, shell injection, weak MD5, insecure pickle, hardcoded AWS key). Catches 16 real findings with `--config auto`.

`core/rules/basic-security.yaml` — small offline ruleset (3 rules), for testing without registry access.

---

## Known environment notes

- **PDF export needs system libraries** (WeasyPrint). If you see "PDF skipped":
```bash
  sudo apt-get update
  sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev
```
- **Re-running a scan is safe** — duplicate findings are automatically deduped; already-explained findings are skipped (no wasted AI calls).

---

## Notes for Part 03 / Part 05 (Rabia)

- Part 03 should call `scan_into_state()` (`core/scanner.py`) on save, then `explain_finding()` (`ai-layer/explain.py`) for inline messages.
- All state read/write goes through `core/state.py` — use `load_state()`, `add_findings()`, `attach_explanation()`, `unexplained_findings()`.
- Part 05 is fully standalone — no dependency on Parts 01/02/04/06.
