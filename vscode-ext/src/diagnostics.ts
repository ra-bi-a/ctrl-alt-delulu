import * as vscode from 'vscode';
import * as fs from 'fs/promises';
import * as path from 'path';
import { getStatePath, getWorkspaceRoot } from './config';

export interface Explanation {
  rule_id: string;
  file_path: string;
  start_line: number;
  plain_summary: string;
  why_it_matters: string;
  how_to_fix: string;
  severity_plain: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  message: string;
  file_path: string;
  start_line: number;
  end_line: number;
  code_snippet: string;
  status: 'open' | 'fixed';
  source: string;
  explanation: Explanation | null;
  metadata: Record<string, unknown>;
}

interface ScanState {
  findings: Finding[];
}

const SEVERITY_MAP: Record<Finding['severity'], vscode.DiagnosticSeverity> = {
  Critical: vscode.DiagnosticSeverity.Error,
  High: vscode.DiagnosticSeverity.Error,
  Medium: vscode.DiagnosticSeverity.Warning,
  Low: vscode.DiagnosticSeverity.Information,
};

/**
 * Owns the one DiagnosticCollection for the whole extension. Every write
 * path (core scanner, pkg-checker, paste-guard) lands in the same
 * scan-state.json, so refresh() just re-reads the whole file and redraws
 * everything — simpler and less bug-prone than trying to patch in only
 * what changed, and cheap enough at hackathon scale to not matter.
 */
export class FindingsDiagnostics {
  private collection: vscode.DiagnosticCollection;

  constructor(context: vscode.ExtensionContext) {
    this.collection = vscode.languages.createDiagnosticCollection('ctrlAltDelulu');
    context.subscriptions.push(this.collection);
  }

  async refresh(): Promise<void> {
    let state: ScanState;
    try {
      const raw = await fs.readFile(getStatePath(), 'utf8');
      state = JSON.parse(raw) as ScanState;
    } catch (err) {
      console.error('Ctrl+Alt+Delulu: could not read scan-state.json:', err);
      return;
    }

    let workspaceRoot: string;
    try {
      workspaceRoot = getWorkspaceRoot();
    } catch {
      return;
    }

    const byFile = new Map<string, vscode.Diagnostic[]>();

    for (const finding of state.findings ?? []) {
      if (finding.status !== 'open') {
        continue;
      }

      const absPath = path.isAbsolute(finding.file_path)
        ? finding.file_path
        : path.join(workspaceRoot, finding.file_path);

      // scan-state.json lines are 1-indexed; VS Code positions are 0-indexed.
      const startLine = Math.max(0, (finding.start_line || 1) - 1);
      const endLine = Math.max(startLine, (finding.end_line || finding.start_line || 1) - 1);
      const range = new vscode.Range(startLine, 0, endLine, Number.MAX_SAFE_INTEGER);

      const diagnostic = new vscode.Diagnostic(
        range,
        formatMessage(finding),
        SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning
      );
      diagnostic.source = `Ctrl+Alt+Delulu (${finding.source})`;
      diagnostic.code = finding.rule_id;

      const existing = byFile.get(absPath) ?? [];
      existing.push(diagnostic);
      byFile.set(absPath, existing);
    }

    this.collection.clear();
    for (const [filePath, diagnostics] of byFile) {
      this.collection.set(vscode.Uri.file(filePath), diagnostics);
    }
  }
}

function formatMessage(finding: Finding): string {
  // Before Part 02 has explained it: just the raw technical message.
  // After: the plain-language version, which is the whole point of the project.
  if (!finding.explanation) {
    return finding.message;
  }
  const exp = finding.explanation;
  return `${exp.plain_summary}\n\nWhy it matters: ${exp.why_it_matters}\n\nHow to fix: ${exp.how_to_fix}`;
}
