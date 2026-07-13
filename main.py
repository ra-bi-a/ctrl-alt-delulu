"""
Ctrl+Alt+Delulu — Parts 01 + 02 combined pipeline
Owner: Sumaira

Runs the Core Scanner (Part 01) on a target codebase, writes results into
the shared scan-state.json, then feeds every finding through the AI
Explanation Layer (Part 02) and writes explanations back into the same
file — so Part 03/04/05/06 all read from one consistent source of truth.

Requires scan-state.json to already exist — run `python init_scan_state.py`
from the repo root once, before using this.

Usage:
    export NVIDIA_API_KEY="nvapi-..."   # or ANTHROPIC_API_KEY, see ai-layer/explain.py
    python main.py path/to/codebase [--config auto|path/to/rules.yaml]
"""

import argparse
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()  # picks up NVIDIA_API_KEY etc. from a local .env file, if present
except ImportError:
    pass

sys.path.insert(0, "core")
sys.path.insert(0, "ai-layer")

import state as scan_state                        # shared scan-state.json helpers
from scanner import scan, save_findings            # Part 01
from explain import explain_findings, save_explanations, print_explanation  # Part 02


def main():
    parser = argparse.ArgumentParser(description="Scan a codebase and explain the findings in plain language.")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--config",
        default="auto",
        help='Semgrep config: "auto" (registry, needs internet) or a path to a local rules.yaml',
    )
    parser.add_argument("--state", default="scan-state.json", help="Path to the shared scan-state.json")
    parser.add_argument("--skip-ai", action="store_true", help="Only run the scanner, skip AI explanations")
    args = parser.parse_args()

    # Fail fast with a clear message if scan-state.json hasn't been created yet.
    try:
        state = scan_state.load_state(args.state)
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)

    print(f"🔍 Scanning {args.target} with Semgrep (config: {args.config}) ...")
    findings = scan(args.target, config=args.config)
    save_findings(findings, "findings.json")  # kept for quick local debugging
    print(f"   Found {len(findings)} issue(s).")

    scan_state.add_findings(state, findings, project_path=args.target)
    scan_state.save_state(state, args.state)
    print(f"   {args.state} now has {state['stats']['total']} total open+fixed finding(s) tracked.\n")

    to_explain = scan_state.unexplained_findings(state)

    if not to_explain:
        print("Nothing new to explain — all tracked findings already have explanations. 🎉")
        return

    if args.skip_ai:
        print(f"(--skip-ai set, leaving {len(to_explain)} finding(s) unexplained for now)")
        return

    print(f"🤖 Explaining {len(to_explain)} new finding(s) with AI ...")
    explanations = explain_findings(to_explain)

    for exp in explanations:
        print_explanation(exp)

    save_explanations(explanations, "explanations.json")  # kept for quick local debugging

    # Re-load state fresh in case it changed, then attach each explanation
    # to its matching finding entry.
    state = scan_state.load_state(args.state)
    attached = 0
    for exp in explanations:
        if scan_state.attach_explanation(
            state, exp.rule_id, exp.file_path, exp.start_line, exp.to_dict()
        ):
            attached += 1
    scan_state.save_state(state, args.state)

    print(f"\n\n✅ Saved {len(explanations)} explanation(s) to explanations.json")
    print(f"✅ Attached {attached}/{len(explanations)} explanation(s) into {args.state}")


if __name__ == "__main__":
    main()