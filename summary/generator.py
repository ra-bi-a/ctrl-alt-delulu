"""
Part 06 — Summary Card Generator
Owner: Taz

Triggered when the developer says "development is ended."
Reads everything from scan-state.json (written by Parts 01, 04, 05),
detects the full tech stack from the project folder, and outputs a
complete project summary in three formats:

    project-summary.json   machine-readable, for Part 03 to display
    project-summary.txt    plain text card — paste anywhere
    project-summary.html   styled HTML card — open in browser, shareable

Uses core/state.py for all state file operations so it stays in sync
with how Parts 01 and 02 wrote the data.

Standalone usage (run from repo root):
    python summary/generator.py
    python summary/generator.py --state scan-state.json --project .

Integration hook (called by Part 03 VS Code "Generate Summary" command):
    import sys
    sys.path.insert(0, "summary")
    from generator import run_summary
    result = run_summary(state_path, project_path)
"""

import json
import os
import sys
import argparse
from datetime import datetime, timezone

# ── Import shared state helpers from core/state.py ───────────────────────────
_CORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core")
sys.path.insert(0, _CORE_PATH)
import state as scan_state

# ── Language detection ────────────────────────────────────────────────────────

# Extension → language label mapping
EXT_MAP = {
    ".py":      "Python",
    ".ts":      "TypeScript",
    ".tsx":     "TypeScript / React",
    ".jsx":     "JavaScript / React",
    ".js":      "JavaScript / Node.js",
    ".vue":     "Vue.js",
    ".svelte":  "Svelte",
    ".rb":      "Ruby",
    ".go":      "Go",
    ".rs":      "Rust",
    ".java":    "Java",
    ".cs":      "C#",
    ".cpp":     "C++",
    ".c":       "C",
    ".php":     "PHP",
    ".swift":   "Swift",
    ".kt":      "Kotlin",
    ".html":    "HTML",
    ".css":     "CSS",
    ".scss":    "SCSS",
}

# Root-level indicator files
ROOT_INDICATORS = {
    "requirements.txt": "Python",
    "setup.py":         "Python",
    "pyproject.toml":   "Python",
    "Pipfile":          "Python",
    "package.json":     "JavaScript / Node.js",
    "tsconfig.json":    "TypeScript",
    "Gemfile":          "Ruby",
    "go.mod":           "Go",
    "Cargo.toml":       "Rust",
    "pom.xml":          "Java (Maven)",
    "build.gradle":     "Java (Gradle)",
    "composer.json":    "PHP",
    "Dockerfile":       "Docker",
    "docker-compose.yml": "Docker Compose",
}

# Folders to skip when walking the project tree
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", ".nuxt", "coverage", ".pytest_cache",
    "site-packages",
}

def detect_languages(project_path="."):
    """
    Walks the project directory and returns a sorted list of detected languages.
    Checks root-level indicator files first (fast), then extensions (deeper).
    """
    detected = set()

    # Root-level indicators
    for filename, language in ROOT_INDICATORS.items():
        if os.path.exists(os.path.join(project_path, filename)):
            detected.add(language)

    # Extension-based walk (capped at 4 levels deep)
    try:
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            depth = root.replace(project_path, "").count(os.sep)
            if depth > 4:
                continue
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext in EXT_MAP:
                    detected.add(EXT_MAP[ext])
    except PermissionError:
        pass

    return sorted(detected)

# ── Package detection ─────────────────────────────────────────────────────────

def detect_packages(project_path="."):
    """
    Reads requirements.txt and/or package.json and returns a dict of
    { package_name: version } for all dependencies found.
    """
    packages = {}

    # Python — requirements.txt
    req_path = os.path.join(project_path, "requirements.txt")
    if os.path.exists(req_path):
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    if "==" in line:
                        name, version = line.split("==", 1)
                        packages[name.strip()] = version.strip()
                    elif any(op in line for op in [">=", "<=", "!="]):
                        name = line.split(">=")[0].split("<=")[0].split("!=")[0].strip()
                        packages[name.split("[")[0].strip()] = "see requirements.txt"
                    else:
                        packages[line.split("[")[0].strip()] = "unversioned"
        except Exception as e:
            print(f"[summary] Could not read requirements.txt: {e}")

    # Node.js — package.json
    pkg_path = os.path.join(project_path, "package.json")
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            packages.update(data.get("dependencies", {}))
            packages.update(data.get("devDependencies", {}))
        except Exception as e:
            print(f"[summary] Could not read package.json: {e}")

    return packages

# ── Security score ────────────────────────────────────────────────────────────

def calculate_score(findings):
    """
    Security score out of 100.
    Starts at 100 and deducts per unfixed finding by severity.
    Severity values from the repo use "High"/"Medium"/"Low"/"Critical"
    (capitalised, as written by core/state.py).
    """
    if not findings:
        return 100

    deductions = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}
    score = 100

    for f in findings:
        if f.get("status") != "fixed":
            sev = f.get("severity", "Low")
            score -= deductions.get(sev, 3)

    # Each fixed finding gives a small bonus
    fixed_count = sum(1 for f in findings if f.get("status") == "fixed")
    score += fixed_count * 5

    return max(0, min(100, score))

# ── Summary builder ───────────────────────────────────────────────────────────

def build_summary(state, languages, packages):
    """
    Merges state file data with detected stack info into one summary dict.

    Reads findings in the format written by core/state.py:
      - finding["file_path"]       flat string, not location.file
      - finding["message"]         not title
      - finding["explanation"]     dict or None (written by Part 02)
      - finding["severity"]        "High" / "Medium" / "Low" / "Critical"
      - finding["source"]          "core-scanner" / "pkg-checker" / "paste-guard"
    """
    findings = state.get("findings", [])
    total     = len(findings)
    fixed     = sum(1 for f in findings if f.get("status") == "fixed")
    open_cnt  = sum(1 for f in findings if f.get("status") == "open")
    dismissed = sum(1 for f in findings if f.get("status") == "dismissed")

    by_type = {"vulnerability": 0, "typosquatting": 0, "secret": 0}
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_source = {}

    for f in findings:
        ftype = f.get("type", "vulnerability")
        if ftype in by_type:
            by_type[ftype] += 1

        sev = f.get("severity", "Low")
        if sev in by_severity:
            by_severity[sev] += 1

        src = f.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

    return {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "generated_by":  "Ctrl+Alt+Delulu — Part 06: Summary Card Generator",
        "project": {
            **state.get("project", {}),
            "ended":     datetime.now(timezone.utc).isoformat(),
            "languages": languages,
            "packages":  packages,
        },
        "stack": {
            "languages":      languages,
            "total_packages": len(packages),
            "packages":       packages,
        },
        "security": {
            "score":          calculate_score(findings),
            "total_findings": total,
            "fixed":          fixed,
            "open":           open_cnt,
            "dismissed":      dismissed,
            "by_type":        by_type,
            "by_severity":    by_severity,
            "by_source":      by_source,
        },
        "findings": findings,
    }

# ── Output: JSON ──────────────────────────────────────────────────────────────

def write_json(summary, output_dir="."):
    path = os.path.join(output_dir, "project-summary.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[summary] JSON  → {path}")
    return path

# ── Output: plain text ────────────────────────────────────────────────────────

def write_text_card(summary, output_dir="."):
    path = os.path.join(output_dir, "project-summary.txt")
    s = summary["security"]
    p = summary["project"]
    score = s["score"]
    score_label = "GOOD" if score >= 80 else ("NEEDS ATTENTION" if score >= 50 else "AT RISK")

    lines = [
        "=" * 56,
        "  CTRL+ALT+DELULU — PROJECT SUMMARY CARD",
        "=" * 56,
        f"  Project   : {p.get('name', 'Unknown')}",
        f"  Generated : {summary['generated_at'][:10]}",
        f"  Path      : {p.get('path', 'Unknown')}",
        "",
        "  ── TECH STACK ──────────────────────────────────────",
        "",
        "  Languages detected:",
    ]

    for lang in summary["stack"]["languages"]:
        lines.append(f"    • {lang}")

    lines += [
        "",
        f"  Packages: {summary['stack']['total_packages']} total",
    ]
    for name, version in list(summary["stack"]["packages"].items())[:20]:
        lines.append(f"    • {name}: {version}")
    if len(summary["stack"]["packages"]) > 20:
        lines.append(f"    ... and {len(summary['stack']['packages']) - 20} more")

    lines += [
        "",
        "  ── SECURITY SUMMARY ────────────────────────────────",
        "",
        f"  Security Score : {score}/100  ({score_label})",
        f"  Total findings : {s['total_findings']}",
        f"  Fixed          : {s['fixed']}",
        f"  Still open     : {s['open']}",
        f"  Dismissed      : {s['dismissed']}",
        "",
        "  By type:",
        f"    Vulnerabilities : {s['by_type'].get('vulnerability', 0)}",
        f"    Typosquatting   : {s['by_type'].get('typosquatting', 0)}",
        f"    Secrets exposed : {s['by_type'].get('secret', 0)}",
        "",
        "  By severity:",
        f"    Critical : {s['by_severity'].get('Critical', 0)}",
        f"    High     : {s['by_severity'].get('High', 0)}",
        f"    Medium   : {s['by_severity'].get('Medium', 0)}",
        f"    Low      : {s['by_severity'].get('Low', 0)}",
        "",
        "  Found by:",
        f"    Core Scanner  : {s['by_source'].get('core-scanner', 0)} findings",
        f"    Pkg Checker   : {s['by_source'].get('pkg-checker', 0)} findings",
        f"    Paste Guard   : {s['by_source'].get('paste-guard', 0)} findings",
        "",
        "=" * 56,
        "  ctrl+alt+delulu  ✦  three women. one scanner. zero jargon.",
        "=" * 56,
    ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[summary] TEXT  → {path}")
    return path

# ── Output: HTML card ─────────────────────────────────────────────────────────

def write_html_card(summary, output_dir="."):
    """
    Styled HTML summary card in the Ctrl+Alt+Delulu theme.
    Open in any browser — shareable with the team or judges.

    Reads Part 02's explanation format correctly:
      finding["explanation"]["plain_summary"]
      finding["explanation"]["how_to_fix"]
    Falls back to finding["message"] if explanation is None (Part 02 not run yet).
    """
    path = os.path.join(output_dir, "project-summary.html")
    s = summary["security"]
    p = summary["project"]
    score = s["score"]
    score_color = "#00FF88" if score >= 80 else ("#FFD700" if score >= 50 else "#FF2D8B")
    score_label = "GOOD" if score >= 80 else ("NEEDS ATTENTION" if score >= 50 else "AT RISK")

    sev_colors = {
        "Critical": "#FF2D8B", "High": "#FF8C42",
        "Medium":   "#FFD700", "Low":  "#7B78A8",
    }

    # Language badges
    lang_badges = "".join(
        f'<span style="display:inline-block;background:rgba(155,111,255,0.15);'
        f'color:#9B6FFF;border:1px solid rgba(155,111,255,0.3);border-radius:4px;'
        f'padding:3px 9px;margin:3px;font-size:11px;">{lang}</span>'
        for lang in summary["stack"]["languages"]
    ) or '<span style="color:#7B78A8;">None detected</span>'

    # Package rows (first 30)
    pkg_rows = ""
    for name, version in list(summary["stack"]["packages"].items())[:30]:
        pkg_rows += (
            f'<tr><td style="color:#C8C5F0;">{name}</td>'
            f'<td style="color:#9B6FFF;font-family:monospace;">{version}</td></tr>'
        )

    # Findings rows (first 50)
    # Reads explanation dict written by Part 02, falls back to message if not yet explained
    finding_rows = ""
    for f in summary["findings"][:50]:
        sev   = f.get("severity", "Low")
        color = sev_colors.get(sev, "#7B78A8")

        explanation = f.get("explanation")
        if explanation and isinstance(explanation, dict):
            display_text = explanation.get("plain_summary", f.get("message", ""))[:150]
        else:
            display_text = f.get("message", "")[:150]

        finding_rows += (
            f'<tr>'
            f'<td style="color:{color};font-family:monospace;font-size:9px;white-space:nowrap;">{sev}</td>'
            f'<td style="color:#E8E5FF;font-size:10px;">{f.get("file_path","")}</td>'
            f'<td style="color:#A0A0C8;font-size:10px;">{display_text}...</td>'
            f'<td style="color:#7B78A8;font-size:9px;">{f.get("source","")}</td>'
            f'<td style="color:#7B78A8;font-size:9px;">{f.get("status","")}</td>'
            f'</tr>'
        )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Ctrl+Alt+Delulu — Project Summary</title>
<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&family=Inter:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0D0B1E;color:#E8E5FF;font-family:'Inter',system-ui,sans-serif;
        font-size:12px;line-height:1.6;padding:20px}}
  .card{{background:#1C1A35;border:1px solid rgba(155,111,255,0.2);
         border-radius:8px;padding:16px;margin-bottom:14px}}
  .sec-t{{font-family:'Press Start 2P',monospace;font-size:8px;color:#00D9FF;margin-bottom:12px}}
  table{{width:100%;border-collapse:collapse}}
  th{{font-family:'Press Start 2P',monospace;font-size:7px;color:#7B78A8;
      text-align:left;padding:7px 10px;border-bottom:1px solid rgba(155,111,255,0.2);
      background:#141230}}
  td{{padding:7px 10px;border-bottom:1px solid rgba(155,111,255,0.08);vertical-align:top}}
  .grid4{{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px}}
  .stat{{background:#141230;border-radius:6px;padding:12px;text-align:center}}
  .stat-n{{font-family:'Press Start 2P',monospace;font-size:18px;margin-bottom:5px}}
  .stat-l{{font-size:10px;color:#7B78A8}}
  .dl-btn{{display:inline-flex;align-items:center;gap:8px;background:#9B6FFF;
            color:#0D0B1E;font-family:'Press Start 2P',monospace;font-size:8px;
            border:none;border-radius:6px;padding:10px 16px;cursor:pointer;margin-bottom:18px}}
  .dl-btn:hover{{background:#b494ff}}
  @media print{{.dl-btn{{display:none}}}}
</style>
<script>
function downloadPDF() {{
  var btn = document.querySelector('.dl-btn');
  btn.style.display = 'none';
  var opt = {{
    margin: 8,
    filename: 'project-summary.pdf',
    image: {{type:'jpeg',quality:0.98}},
    html2canvas: {{scale:2, backgroundColor:'#0D0B1E', useCORS:true}},
    jsPDF: {{unit:'mm',format:'a4',orientation:'portrait'}}
  }};
  html2pdf().set(opt).from(document.getElementById('summary-content')).save()
    .then(function(){{ btn.style.display = ''; }});
}}
</script>
</head>
<body>
<button class="dl-btn" onclick="downloadPDF()">&#11015; Download PDF</button>
<div id="summary-content">

<div style="display:flex;align-items:center;gap:8px;margin-bottom:20px">
  <div style="background:#9B6FFF;width:26px;height:26px;border-radius:5px;
       display:flex;align-items:center;justify-content:center;
       font-family:'Press Start 2P',monospace;font-size:9px;color:#0D0B1E">X</div>
  <div style="background:#FF2D8B;width:26px;height:26px;border-radius:5px;
       display:flex;align-items:center;justify-content:center;
       font-family:'Press Start 2P',monospace;font-size:9px;color:#0D0B1E">A</div>
  <div style="background:#00D9FF;width:26px;height:26px;border-radius:5px;
       display:flex;align-items:center;justify-content:center;
       font-family:'Press Start 2P',monospace;font-size:9px;color:#0D0B1E">O</div>
  <div>
    <div style="font-family:'Press Start 2P',monospace;font-size:11px;color:#9B6FFF">
        PROJECT SUMMARY CARD</div>
    <div style="font-size:10px;color:#7B78A8;margin-top:3px">
        {p.get('name','Unknown')} &nbsp;·&nbsp; {summary['generated_at'][:10]}</div>
  </div>
</div>

<div class="card" style="border-left:3px solid {score_color}">
  <div class="sec-t">✦ SECURITY SCORE</div>
  <div style="display:flex;align-items:center;gap:20px">
    <div>
      <div style="font-family:'Press Start 2P',monospace;font-size:28px;
                  color:{score_color}">{score}</div>
      <div style="font-family:'Press Start 2P',monospace;font-size:9px;
                  color:{score_color};margin-top:5px">{score_label}</div>
    </div>
    <div class="grid4" style="flex:1">
      <div class="stat">
        <div class="stat-n" style="color:#E8E5FF">{s['total_findings']}</div>
        <div class="stat-l">Total</div>
      </div>
      <div class="stat">
        <div class="stat-n" style="color:#00FF88">{s['fixed']}</div>
        <div class="stat-l">Fixed</div>
      </div>
      <div class="stat">
        <div class="stat-n" style="color:#FF2D8B">{s['open']}</div>
        <div class="stat-l">Open</div>
      </div>
      <div class="stat">
        <div class="stat-n" style="color:#7B78A8">{s['dismissed']}</div>
        <div class="stat-l">Dismissed</div>
      </div>
    </div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
  <div class="card">
    <div class="sec-t">✦ BY TYPE</div>
    <table>
      <tr><td style="color:#C8C5F0">Vulnerabilities</td>
          <td style="color:#FF2D8B;font-weight:600;text-align:right">
              {s['by_type'].get('vulnerability',0)}</td></tr>
      <tr><td style="color:#C8C5F0">Typosquatting</td>
          <td style="color:#FFD700;font-weight:600;text-align:right">
              {s['by_type'].get('typosquatting',0)}</td></tr>
      <tr><td style="color:#C8C5F0">Secrets Exposed</td>
          <td style="color:#9B6FFF;font-weight:600;text-align:right">
              {s['by_type'].get('secret',0)}</td></tr>
    </table>
  </div>
  <div class="card">
    <div class="sec-t">✦ BY SEVERITY</div>
    <table>
      <tr><td style="color:#C8C5F0">Critical</td>
          <td style="color:#FF2D8B;font-weight:600;text-align:right">
              {s['by_severity'].get('Critical',0)}</td></tr>
      <tr><td style="color:#C8C5F0">High</td>
          <td style="color:#FF8C42;font-weight:600;text-align:right">
              {s['by_severity'].get('High',0)}</td></tr>
      <tr><td style="color:#C8C5F0">Medium</td>
          <td style="color:#FFD700;font-weight:600;text-align:right">
              {s['by_severity'].get('Medium',0)}</td></tr>
      <tr><td style="color:#C8C5F0">Low</td>
          <td style="color:#7B78A8;font-weight:600;text-align:right">
              {s['by_severity'].get('Low',0)}</td></tr>
    </table>
  </div>
</div>

<div class="card">
  <div class="sec-t">✦ TECH STACK — LANGUAGES</div>
  <div>{lang_badges}</div>
</div>

<div class="card">
  <div class="sec-t">✦ PACKAGES ({summary['stack']['total_packages']} total)</div>
  <table>
    <tr><th>Package</th><th>Version</th></tr>
    {pkg_rows or '<tr><td colspan="2" style="color:#7B78A8">No packages detected</td></tr>'}
  </table>
  {'<div style="color:#7B78A8;font-size:10px;margin-top:8px">Showing first 30. See project-summary.json for full list.</div>' if len(summary['stack']['packages']) > 30 else ''}
</div>

<div class="card">
  <div class="sec-t">✦ ALL FINDINGS</div>
  <table>
    <tr><th>Severity</th><th>File</th><th>Summary</th><th>Source</th><th>Status</th></tr>
    {finding_rows or '<tr><td colspan="5" style="color:#7B78A8">No findings recorded</td></tr>'}
  </table>
  {'<div style="color:#7B78A8;font-size:10px;margin-top:8px">Showing first 50. See project-summary.json for full list.</div>' if len(summary['findings']) > 50 else ''}
</div>

<div style="text-align:center;padding:14px;font-family:\'Press Start 2P\',monospace;
            font-size:8px;border-top:1px solid rgba(155,111,255,0.15);margin-top:10px">
  <span style="color:#9B6FFF">ctrl</span>+<span style="color:#FF2D8B">alt</span>+<span style="color:#00D9FF">delulu</span>
  &nbsp;✦&nbsp;
  <span style="color:#7B78A8;font-size:7px">three women. one scanner. zero jargon.</span>
</div>

</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[summary] HTML  → {path}")
    return path

# ── Output: PDF (optional — needs weasyprint) ────────────────────────────────

def write_pdf(html_path, output_dir="."):
    """
    Converts project-summary.html to project-summary.pdf using WeasyPrint.
    Fully preserves the dark theme and colours.

    Install WeasyPrint once:
        pip install weasyprint

    Skips gracefully if WeasyPrint is not installed — HTML card still works.
    """
    try:
        from weasyprint import HTML, CSS
        path = os.path.join(output_dir, "project-summary.pdf")
        HTML(filename=html_path).write_pdf(
            path,
            stylesheets=[CSS(string="""
                @page { size: A4; margin: 8mm; }
                body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
                .dl-btn { display: none !important; }
            """)]
        )
        print(f"[summary] PDF   → {path}")
        return path
    except ImportError:
        print("[summary] PDF skipped — WeasyPrint not installed.")
        print("[summary] To enable: pip install weasyprint")
        return None
    except Exception as e:
        print(f"[summary] PDF generation failed: {e}")
        return None

# ── Update state with end info ────────────────────────────────────────────────

def finalise_state(state, state_path, languages, packages):
    """Writes the ended timestamp, languages, and packages back into scan-state.json."""
    state["project"]["ended"]     = datetime.now(timezone.utc).isoformat()
    state["project"]["languages"] = languages
    state["project"]["packages"]  = packages
    scan_state.save_state(state, state_path)
    print(f"[summary] Updated {state_path} with project end data")

# ── Integration hook for Part 03 ──────────────────────────────────────────────

def run_summary(state_path="scan-state.json", project_path=".", output_dir="."):
    """
    THE MAIN INTEGRATION POINT — Part 03 calls this when the developer
    triggers "Generate Summary" in VS Code.

    Usage from Part 03:
        import sys
        sys.path.insert(0, "summary")
        from generator import run_summary
        result = run_summary("scan-state.json", "/path/to/project")
    """
    print("\n[summary] Generating project summary...\n")

    state     = scan_state.load_state(state_path)
    languages = detect_languages(project_path)
    packages  = detect_packages(project_path)

    print(f"[summary] Languages: {', '.join(languages) or 'none detected'}")
    print(f"[summary] Packages:  {len(packages)} found")

    summary = build_summary(state, languages, packages)

    finalise_state(state, state_path, languages, packages)

    write_json(summary, output_dir)
    write_text_card(summary, output_dir)
    html_path = write_html_card(summary, output_dir)
    write_pdf(html_path, output_dir)

    s = summary["security"]
    print(f"""
[summary] ✓  Done!

  Security Score : {s['score']}/100
  Findings       : {s['total_findings']} total / {s['fixed']} fixed / {s['open']} open
  Languages      : {', '.join(languages) or 'none'}
  Packages       : {len(packages)}

  Open project-summary.html in your browser for the full card.
  Click the purple Download PDF button to save as PDF.
""")

    return summary

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Ctrl+Alt+Delulu — Part 06: Summary Card Generator"
    )
    parser.add_argument("--state",   default="scan-state.json",
                        help="Path to scan-state.json (default: scan-state.json)")
    parser.add_argument("--project", default=".",
                        help="Project folder to detect stack from (default: .)")
    parser.add_argument("--output",  default=".",
                        help="Folder to write summary files into (default: .)")
    args = parser.parse_args()

    run_summary(
        state_path=os.path.abspath(args.state),
        project_path=os.path.abspath(args.project),
        output_dir=os.path.abspath(args.output),
    )

if __name__ == "__main__":
    main()