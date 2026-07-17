import * as vscode from 'vscode';
import * as path from 'path';
import { runPasteGuard, Finding, RunPasteGuardOptions } from './pythonBridge';

// Pastes shorter than this are almost never worth scanning (single words,
// short variable names). Tune as needed.
const MIN_LENGTH_TO_SCAN = 15;

// If the scan resolves faster than this, no UI is shown at all — the paste
// just completes. Measured against the real guard.py: cold Python startup +
// regex scan averages ~40-50ms, so in practice this notification should
// rarely surface. It stays in as a safety net for slower machines rather
// than something expected to fire on every paste.
const PROGRESS_DISPLAY_DELAY_MS = 250;

// TODO once the extension is actually scaffolded: these two paths assume
// paste-guard/guard.py and scan-state.json sit at the repo root, one level
// up from wherever vscode-ext's compiled output lands. Confirm the real
// layout (and whether the extension bundles its own copy of guard.py vs.
// referencing the sibling repo folder) before wiring this in for real.
const GUARD_SCRIPT_PATH = path.join(__dirname, '..', '..', 'paste-guard', 'guard.py');
const STATE_PATH = path.join(__dirname, '..', '..', 'scan-state.json');

export function registerPasteGuard(context: vscode.ExtensionContext) {
  const disposable = vscode.commands.registerCommand('pasteGuard.interceptPaste', handlePaste);
  context.subscriptions.push(disposable);
}

async function handlePaste() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    return;
  }

  const clipboardText = await vscode.env.clipboard.readText();
  if (!clipboardText || clipboardText.trim().length < MIN_LENGTH_TO_SCAN) {
    return defaultPaste();
  }

  const filePath = editor.document.uri.fsPath;
  const line = editor.selection.active.line + 1; // VS Code positions are 0-indexed; scan-state.json lines are 1-indexed

  const baseOptions: RunPasteGuardOptions = {
    filePath,
    line,
    statePath: STATE_PATH,
    guardScriptPath: GUARD_SCRIPT_PATH,
  };

  let findings: Finding[] = [];
  try {
    findings = await scanWithVisibleProgress(clipboardText, baseOptions);
  } catch (err) {
    // Fail OPEN, not closed: if Python/guard.py is missing, errors, or
    // times out, we never want a tooling failure to block a legitimate paste.
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
  // wait on a second Python invocation after they already said "go ahead."
  runPasteGuard(clipboardText, { ...baseOptions, write: true }).catch((err) =>
    console.error('Paste Guard: failed to log confirmed paste:', err)
  );

  return defaultPaste();
}

/**
 * Runs the scan, but only shows a visible "in progress" indicator if it's
 * still running after PROGRESS_DISPLAY_DELAY_MS. Fast scans (the expected
 * common case) resolve silently; slow ones get a clear notice so the user
 * isn't left wondering whether the paste silently failed.
 */
async function scanWithVisibleProgress(text: string, options: RunPasteGuardOptions): Promise<Finding[]> {
  const scanPromise = runPasteGuard(text, options);

  let settled = false;
  scanPromise.finally(() => {
    settled = true;
  });

  await new Promise((resolve) => setTimeout(resolve, PROGRESS_DISPLAY_DELAY_MS));

  if (settled) {
    return scanPromise;
  }

  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Paste Guard: code scan in progress…',
      cancellable: false,
    },
    () => scanPromise
  );
}

async function showFindingsPrompt(findings: Finding[]): Promise<boolean> {
  const summary = findings.map((f) => `Line ${f.start_line}: ${f.message}`).join('\n\n');

  const choice = await vscode.window.showWarningMessage(
    `Paste Guard found ${findings.length} potential secret(s) in this paste:\n\n${summary}`,
    { modal: true },
    'Paste Anyway',
    'Cancel'
  );

  return choice === 'Paste Anyway';
}

function defaultPaste() {
  return vscode.commands.executeCommand('editor.action.clipboardPasteAction');
}
