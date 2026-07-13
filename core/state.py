"""
core/state.py — shared scan-state.json read/write helpers
Used by Part 01 (writes findings) and Part 02 (reads findings, writes
explanations back in) so every part speaks the same file format.

scan-state.json itself is created once by init_scan_state.py at the repo
root (Tasneem's script) — this module never creates it from scratch, it
only reads/updates an existing one.
"""

import json
from pathlib import Path
from typing import Any

DEFAULT_STATE_PATH = "scan-state.json"

# Semgrep only gives us ERROR / WARNING / INFO. We map that to the
# Low/Medium/High buckets scan-state.json expects. "Critical" is reserved
# for the AI layer's own judgment call (Part 02's severity_plain) once a
# finding has been explained.
_SEMGREP_SEVERITY_MAP = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}


def load_state(path: str = DEFAULT_STATE_PATH) -> dict[str, Any]:
    """Load scan-state.json. Raises a clear error if it doesn't exist yet."""
    state_path = Path(path)
    if not state_path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run `python init_scan_state.py` from the "
            "repo root first (once, before any part touches the codebase)."
        )
    with open(state_path) as f:
        return json.load(f)


def save_state(state: dict[str, Any], path: str = DEFAULT_STATE_PATH) -> None:
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def _severity_from_semgrep(raw_severity: str) -> str:
    return _SEMGREP_SEVERITY_MAP.get(raw_severity.upper(), "Medium")


def _type_from_rule_id(rule_id: str) -> str:
    """Best-effort guess at finding type from the semgrep rule id/name."""
    rid = rule_id.lower()
    if "secret" in rid or "credential" in rid or "hardcoded" in rid and "key" in rid:
        return "secret"
    if "typosquat" in rid:
        return "typosquatting"
    return "vulnerability"


def finding_to_state_entry(finding: Any, entry_id: str) -> dict[str, Any]:
    """
    Convert a core.scanner.Finding into a scan-state.json findings[] entry.
    `finding` can be a Finding dataclass or an equivalent dict (has the
    same fields via .to_dict() / already-dict findings.json content).
    """
    f = finding.to_dict() if hasattr(finding, "to_dict") else finding

    return {
        "id": entry_id,
        "rule_id": f["rule_id"],
        "type": _type_from_rule_id(f["rule_id"]),
        "severity": _severity_from_semgrep(f.get("severity", "WARNING")),
        "message": f["message"],
        "file_path": f["file_path"],
        "start_line": f["start_line"],
        "end_line": f["end_line"],
        "code_snippet": f["code_snippet"],
        "status": "open",
        "source": "core-scanner",
        "explanation": None,
        "metadata": f.get("metadata", {}),
    }


def recompute_stats(state: dict[str, Any]) -> None:
    """Recalculate stats.* from the current findings[] list (source of truth)."""
    findings = state.get("findings", [])
    stats = state["stats"]

    stats["total"] = len(findings)
    stats["fixed"] = sum(1 for f in findings if f.get("status") == "fixed")
    stats["open"] = stats["total"] - stats["fixed"]

    for bucket in stats["by_type"]:
        stats["by_type"][bucket] = 0
    for bucket in stats["by_severity"]:
        stats["by_severity"][bucket] = 0

    for f in findings:
        ftype = f.get("type", "vulnerability")
        if ftype in stats["by_type"]:
            stats["by_type"][ftype] += 1

        fsev = f.get("severity", "Medium").lower()
        if fsev in stats["by_severity"]:
            stats["by_severity"][fsev] += 1


def add_findings(
    state: dict[str, Any],
    findings: list[Any],
    project_path: str | None = None,
) -> dict[str, Any]:
    """
    Add a batch of Finding objects (from core/scanner.py) into state,
    tagging each with a stable id, and recompute stats. Returns the
    mutated state (also mutates in place).

    Deduplicates against existing OPEN findings (same rule_id + file_path +
    start_line) so re-running a scan on an unchanged codebase doesn't pile
    up duplicate entries — re-scanning is idempotent. A finding that was
    previously marked "fixed" but reappears (regression) IS re-added, since
    that's a genuinely new event worth tracking.
    """
    existing = state.get("findings", [])
    open_keys = {
        (e["rule_id"], e["file_path"], e["start_line"])
        for e in existing
        if e.get("status") == "open"
    }
    next_index = len(existing) + 1
    added = 0

    for finding in findings:
        f = finding.to_dict() if hasattr(finding, "to_dict") else finding
        key = (f["rule_id"], f["file_path"], f["start_line"])
        if key in open_keys:
            continue  # already tracked as an open finding — skip duplicate
        entry_id = f"F-{next_index:04d}"
        existing.append(finding_to_state_entry(finding, entry_id))
        open_keys.add(key)
        next_index += 1
        added += 1

    state["findings"] = existing

    if project_path and not state["project"].get("path"):
        state["project"]["path"] = project_path

    recompute_stats(state)
    return state


def unexplained_findings(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Return finding entries (as dicts, in scan-state.json's own format) that don't have an explanation yet."""
    return [e for e in state.get("findings", []) if e.get("status") == "open" and not e.get("explanation")]


def attach_explanation(
    state: dict[str, Any],
    rule_id: str,
    file_path: str,
    start_line: int,
    explanation: dict[str, Any],
) -> bool:
    """
    Find the matching finding entry (by rule_id + file + line) and attach
    an explanation dict to it (from Part 02). Also upgrades severity to
    the AI's severity_plain judgment if provided. Returns True if a match
    was found and updated.
    """
    for entry in state.get("findings", []):
        if (
            entry["rule_id"] == rule_id
            and entry["file_path"] == file_path
            and entry["start_line"] == start_line
        ):
            entry["explanation"] = explanation
            severity_plain = explanation.get("severity_plain")
            if severity_plain:
                entry["severity"] = severity_plain
            recompute_stats(state)
            return True
    return False