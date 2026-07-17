import * as vscode from 'vscode';
import * as path from 'path';
import { runPythonJson } from './pythonRunner';
import { getGuardScriptPath, getStatePath, getWorkspaceRoot } from './config';
import { FindingsDiagnostics } from './diagnostics';

const MIN_LENGTH_TO_SCAN = 15;

// Measured ~40-50ms average against the real guard.py (see paste-guard/README.md).
// This threshold should rarely actually trigger the notification in practice —
// it's a safety net for slower machines, not something expected on every paste.
const PROGRESS_DISPLAY_DELAY_MS = 250;

interface GuardFinding {
  id: string;
  rule_id: string;
  type: string;
  severity: string;
  message: string;
  file_path: string;
  start_line: number;
  end_line: number;
  code_snippet: string;
  status: string;
  source: string;
  explanation: unknown;
  metadata: Record<string, unknown>;
}

interface GuardResult {
  findings: GuardFinding[];
}

export function registerPasteGuard(context: vscode.ExtensionContext, diagnostics: FindingsDiagnostics) {
  const disposable = vscode.commands.registerCommand('ctrlAltDelulu.interceptPaste', () => handlePaste(diagnostics));
  context.subscriptions.push(disposable);
}

async function handlePaste(diagnostics: FindingsDiagnostics) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    return;
  }

  const clipboardText = await vscode.env.clipboard.readText();
  if (!clipboardText || clipboardText.trim().length < MIN_LENGTH_TO_SCAN) {
    return defaultPaste();
  }

  let workspaceRoot: string;
  try {
    workspaceRoot = getWorkspaceRoot();
  } catch {
    return defaultPaste(); // no workspace open — nothing to check against, fail open
  }

  const relativeFilePath = path.relative(workspaceRoot, editor.document.uri.fsPath);
  const line = editor.selection.active.line + 1; // VS Code is 0-indexed; scan-state.json is 1-indexed

  let findings: GuardFinding[] = [];
  try {
    findings = await scanWithVisibleProgress(clipboardText, relativeFilePath, line);
  } catch (err) {
    // Fail OPEN: a broken Python environment should never block a legitimate paste.
    console.error('Paste Guard scan failed:', err);
    return defaultPaste();
  }

  if (findings.length === 0) {
    return defaultPaste();
  }

  const proceed = await showFindingsPrompt(findings);
  if (!proceed) {
    return; // cancelled — clipboard content never inserted, nothing logged
  }

  // Paste immediately; log in the background rather than making the user
  // wait on a second Python call after they already said "go ahead."
  logConfirmedPaste(clipboardText, relativeFilePath, line, diagnostics);
  return defaultPaste();
}

function scanClipboard(text: string, filePath: string, line: number, write: boolean): Promise<GuardResult> {
  return runPythonJson<GuardResult>(getGuardScriptPath(), {
    args: ['--file', filePath, '--line', String(line), '--state', getStatePath(), ...(write ? ['--write'] : [])],
    stdin: text,
  });
}

/**
 * Only shows a visible indicator if the scan is still running past
 * PROGRESS_DISPLAY_DELAY_MS — fast scans (the expected common case)
 * resolve silently.
 */
async function scanWithVisibleProgress(text: string, filePath: string, line: number): Promise<GuardFinding[]> {
  const scanPromise = scanClipboard(text, filePath, line, false);

  let settled = false;
  scanPromise.finally(() => {
    settled = true;
  });

  await new Promise((resolve) => setTimeout(resolve, PROGRESS_DISPLAY_DELAY_MS));

  if (settled) {
    return (await scanPromise).findings;
  }

  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Paste Guard: code scan in progress…',
      cancellable: false,
    },
    async () => (await scanPromise).findings
  );
}

async function showFindingsPrompt(findings: GuardFinding[]): Promise<boolean> {
  const summary = findings.map((f) => `Line ${f.start_line}: ${f.message}`).join('\n\n');
  const choice = await vscode.window.showWarningMessage(
    `Paste Guard found ${findings.length} potential secret(s) in this paste:\n\n${summary}`,
    { modal: true },
    'Paste Anyway',
    'Cancel'
  );
  return choice === 'Paste Anyway';
}

function logConfirmedPaste(text: string, filePath: string, line: number, diagnostics: FindingsDiagnostics) {
  scanClipboard(text, filePath, line, true)
    .then(() => diagnostics.refresh())
    .catch((err) => console.error('Paste Guard: failed to log confirmed paste:', err));
}

function defaultPaste() {
  return vscode.commands.executeCommand('editor.action.clipboardPasteAction');
}
