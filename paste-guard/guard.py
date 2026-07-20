"""
Part 05 — Paste Guard
Owner: Rabia

Scans clipboard content for hardcoded secrets (API keys, tokens, private
keys, passwords) BEFORE it's pasted into the editor, so a credential
never lands in the codebase in the first place.

Scope is deliberately narrow: full vulnerability scanning (SQL injection,
command injection, etc.) is already covered by Part 01's background
Semgrep scan on save. Re-running that here would just duplicate detection
that's already happening for no new value. Paste Guard exists specifically
for secrets, because that's the one category where "catch it after it's
already in the file" is meaningfully worse than "catch it before it
lands" — a leaked key needs rotating even if the line gets deleted five
seconds later.

Deliberately does NOT use Semgrep. Semgrep's pattern rules need
syntactically valid code to match against — see core/rules/basic-
security.yaml's hardcoded-secret rule, which only matches a complete
`VAR = "..."` assignment. Pasted clipboard content is often a fragment
(a bare token, a .env line, a JSON blob, part of an expression) that
won't parse as a full statement, so a Semgrep-based check would silently
miss most real paste-time cases. Plain regex/entropy matching on raw
text has no such requirement and runs in milliseconds.

Standalone usage:
    echo "AKIAIOSFODNN7EXAMPLE" | python paste-guard/guard.py
    echo "..." | python paste-guard/guard.py --file src/app.py --line 42
    echo "..." | python paste-guard/guard.py --write   # also logs to scan-state.json

Integration hook (called by Part 03 VS Code extension):
    from paste_guard.guard import run_check, write_findings_to_state

    # 1. On Ctrl+V, BEFORE the paste is inserted:
    findings = run_check(clipboard_text, file_path="src/app.py", line=42)
    # -> show a confirm dialog listing findings if any; if none, paste immediately.

    # 2. Only if the user clicks "Paste Anyway" on a flagged paste:
    write_findings_to_state(findings, state_path="scan-state.json")
    # A cancelled paste never touched the codebase, so nothing gets logged for it.
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter

# ── Import shared state helpers from core/state.py ───────────────────────────
# Works whether you run this from the repo root or from paste-guard/
_CORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core")
sys.path.insert(0, _CORE_PATH)
import state as scan_state  # load_state, save_state, recompute_stats


# ── Known secret patterns ─────────────────────────────────────────────────────
# Provider-specific formats first (near-zero false-positive rate). Generic
# assignment pattern and entropy fallback last (broader net, more likely
# to catch a false positive — that's an acceptable trade here, since a
# false positive just costs one extra confirm click, never blocks anything
# permanently).

SECRET_PATTERNS = [
    {
        "id": "aws-access-key-id",
        "label": "AWS Access Key ID",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "Critical",
    },
    {
        "id": "github-token",
        "label": "GitHub personal access token",
        "regex": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
        "severity": "Critical",
    },
    {
        "id": "slack-token",
        "label": "Slack token",
        "regex": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b"),
        "severity": "Critical",
    },
    {
        "id": "stripe-live-key",
        "label": "Stripe live API key",
        "regex": re.compile(r"\b(sk|pk)_live_[0-9a-zA-Z]{24,}\b"),
        "severity": "Critical",
    },
    {
        "id": "private-key-block",
        "label": "Private key block",
        "regex": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "severity": "Critical",
    },
    {
        "id": "generic-assignment",
        "label": "Hardcoded credential assignment",
        "regex": re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"password|passwd|pwd|client[_-]?secret)\b\s*[:=]\s*"
            r"['\"]([^'\"]{8,})['\"]"
        ),
        "severity": "High",
    },
    {
        "id": "jwt-like-token",
        "label": "JWT-format token",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "severity": "Medium",
    },
]

# Generic high-entropy fallback: catches secrets that don't match a known
# provider format (custom internal tokens, random-looking config values).
# Lowest-confidence check on purpose, and the one most worth tuning after
# testing on real pastes — long minified strings, base64 data URIs, and
# hashes in test fixtures can all trip this.
ENTROPY_MIN_LENGTH = 20
ENTROPY_THRESHOLD = 4.3  # bits/char — random base64/hex sits ~4.0-4.5, English prose ~3.5-4.0
_CANDIDATE_TOKEN = re.compile(r"['\"]([A-Za-z0-9+/_=.-]{20,})['\"]")
_BARE_TOKEN_CHARSET = re.compile(r"[A-Za-z0-9+/_=.-]+")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _find_high_entropy_strings(text: str):
    """Finds candidate secrets that appear as quoted strings in actual code,
    e.g. `api_key = "abc123..."`. Requires quotes on purpose — see
    _bare_token_if_high_entropy() for the no-quotes case."""
    for match in _CANDIDATE_TOKEN.finditer(text):
        token = match.group(1)
        if len(token) < ENTROPY_MIN_LENGTH:
            continue
        if _shannon_entropy(token) >= ENTROPY_THRESHOLD:
            yield match, token


def _bare_token_if_high_entropy(text: str):
    """Handles someone pasting *just* a secret with nothing else around it —
    e.g. copying an API key by itself and hitting paste with no code
    context at all. _find_high_entropy_strings() above requires quotes,
    which a bare paste like this will never have, so without this check
    it's invisible to every rule except the provider-specific ones (AWS,
    GitHub, etc formats). Deliberately conservative: only fires when the
    *entire* pasted content, once trimmed, is a single token with no
    whitespace — a real code paste practically never looks like that, so
    this shouldn't fire on normal pastes, only on "just the secret" ones.
    """
    stripped = text.strip()
    if not (ENTROPY_MIN_LENGTH <= len(stripped) <= 200):
        return None
    if not _BARE_TOKEN_CHARSET.fullmatch(stripped):
        return None
    if _shannon_entropy(stripped) < ENTROPY_THRESHOLD:
        return None
    return stripped


# ── Finding builder — matches core/state.py's format exactly ─────────────────

def _line_of_match(text: str, match_start: int) -> int:
    """1-indexed line number within the pasted snippet where a match starts."""
    return text.count("\n", 0, match_start) + 1


def _build_finding(entry_id, rule_id, label, severity, matched_text, snippet_line,
                    file_path, base_line):
    # Redact the actual secret value in what gets stored/displayed — the
    # point is to flag that something sensitive is here, not to persist
    # the credential itself into scan-state.json.
    redacted = matched_text[:4] + "…" + matched_text[-2:] if len(matched_text) > 8 else "…"

    return {
        "id": entry_id,
        "rule_id": f"paste-guard.secret.{rule_id}",
        "type": "secret",
        "severity": severity,          # "Critical" / "High" / "Medium" — capitalised to match core
        "message": (
            f"{label} detected in pasted content. Secrets should never be "
            f"committed to source code — rotate this credential if it's real, "
            f"and load it from an environment variable or secrets manager instead."
        ),
        "file_path": file_path or "clipboard",
        "start_line": (base_line or 0) + snippet_line - 1,
        "end_line": (base_line or 0) + snippet_line - 1,
        "code_snippet": redacted,
        "status": "open",
        "source": "paste-guard",
        "explanation": None,           # left None — Part 02 fills this in if this gets pasted anyway
        "metadata": {
            "category": "secrets",
            "cwe": "CWE-798: Use of Hard-coded Credentials",
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            ],
        },
    }


# ── Core check logic ──────────────────────────────────────────────────────────

def check_paste(text, file_path=None, line=None, state=None):
    """
    Scans a block of text (clipboard content, about to be pasted) for
    hardcoded secrets. Returns a list of finding dicts — empty if clean.

    `state` is optional; pass the already-loaded scan-state.json dict if
    you have it, so IDs in this batch continue from the real count.
    Whatever ID gets assigned here is provisional — write_findings_to_state
    re-derives the real ID against the file on disk at write time anyway
    (same as Part 04), so this only needs to be internally consistent
    for display in the confirm dialog.
    """
    if not text or not text.strip():
        return []

    next_index = (len(state.get("findings", [])) if state else 0) + 1
    findings = []
    matched_spans = []  # avoid double-flagging the same text via two rules

    def claim_id():
        nonlocal next_index
        entry_id = f"F-{next_index:04d}"
        next_index += 1
        return entry_id

    for pattern in SECRET_PATTERNS:
        for match in pattern["regex"].finditer(text):
            span = match.span()
            if any(s <= span[0] < e for s, e in matched_spans):
                continue
            matched_spans.append(span)
            snippet_line = _line_of_match(text, span[0])
            # generic-assignment captures keyword + operator + quotes as the
            # full match — redact just the quoted value (group 2), not the
            # keyword too, so e.g. "password: ****" stays legible context.
            value_to_redact = match.group(2) if pattern["id"] == "generic-assignment" else match.group(0)
            findings.append(_build_finding(
                claim_id(), pattern["id"], pattern["label"], pattern["severity"],
                value_to_redact, snippet_line, file_path, line,
            ))

    for match, token in _find_high_entropy_strings(text):
        span = match.span()
        if any(s <= span[0] < e for s, e in matched_spans):
            continue
        matched_spans.append(span)
        snippet_line = _line_of_match(text, span[0])
        findings.append(_build_finding(
            claim_id(), "high-entropy-string", "Possible hardcoded secret (high-entropy string)",
            "Medium", token, snippet_line, file_path, line,
        ))

    # Only check the "bare token, no code context" case if nothing above
    # already caught this paste — avoids a duplicate finding when e.g. an
    # AKIA-format key was pasted bare (already caught by its own pattern).
    if not findings:
        bare_token = _bare_token_if_high_entropy(text)
        if bare_token:
            findings.append(_build_finding(
                claim_id(), "bare-high-entropy-token",
                "Possible hardcoded secret (unlabeled token, no surrounding code)",
                "Medium", bare_token, 1, file_path, line,
            ))

    return findings


# ── State write ───────────────────────────────────────────────────────────────

def write_findings_to_state(findings, state_path="scan-state.json"):
    """
    Appends findings to scan-state.json and recomputes stats. Only call
    this when the user pastes anyway despite the warning — a cancelled
    paste never entered the codebase, so nothing should be logged for it.

    Dedupes on (rule_id, file_path, start_line) — the same key
    core/state.py's add_findings() uses. rule_id alone isn't specific
    enough here: two different AWS keys pasted in two different spots
    both match "paste-guard.secret.aws-access-key", so file_path + line
    is what actually tells them apart.
    """
    if not findings:
        return

    state = scan_state.load_state(state_path)
    existing = state.get("findings", [])

    open_keys = {
        (e["rule_id"], e["file_path"], e["start_line"])
        for e in existing
        if e.get("status") == "open"
    }

    added = 0
    next_index = len(existing) + 1

    for finding in findings:
        key = (finding["rule_id"], finding["file_path"], finding["start_line"])
        if key in open_keys:
            continue
        finding["id"] = f"F-{next_index:04d}"
        existing.append(finding)
        open_keys.add(key)
        next_index += 1
        added += 1

    state["findings"] = existing
    scan_state.recompute_stats(state)
    scan_state.save_state(state, state_path)

    print(f"[paste-guard] Logged {added} finding(s) to {state_path}", file=sys.stderr)


# ── Integration hook for Part 03 ──────────────────────────────────────────────

def run_check(text, file_path=None, line=None, state_path="scan-state.json"):
    """
    THE MAIN INTEGRATION POINT — Part 03 (VS Code extension) calls this
    right after Ctrl+V, BEFORE the paste is inserted. Returns findings
    WITHOUT writing them; call write_findings_to_state() separately, and
    only if the user proceeds past the warning.
    """
    state = None
    if os.path.exists(state_path):
        state = scan_state.load_state(state_path)
    return check_paste(text, file_path=file_path, line=line, state=state)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Ctrl+Alt+Delulu — Part 05: Paste Guard (reads clipboard text from stdin)"
    )
    parser.add_argument("--file", default=None, help="Active file path in the editor")
    parser.add_argument("--line", type=int, default=0, help="Line number the paste will land on")
    parser.add_argument("--state", default="scan-state.json", help="Path to scan-state.json")
    parser.add_argument(
        "--write", action="store_true",
        help="Write findings to scan-state.json. Only pass this on the "
             "confirmed-paste call, not the initial check.",
    )
    args = parser.parse_args()

    text = sys.stdin.read()
    findings = run_check(text, file_path=args.file, line=args.line, state_path=args.state)

    if args.write and findings:
        write_findings_to_state(findings, args.state)

    print(json.dumps({"findings": findings}, indent=2))


if __name__ == "__main__":
    main()
