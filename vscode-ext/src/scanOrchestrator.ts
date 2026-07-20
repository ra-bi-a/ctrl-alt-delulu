import * as vscode from 'vscode';
import * as path from 'path';
import { runPython } from './pythonRunner';
import { getMainScriptPath, getCheckerScriptPath, getStatePath, getWorkspaceRoot } from './config';
import { FindingsDiagnostics } from './diagnostics';

const MANIFEST_FILES = new Set(['requirements.txt', 'package.json']);

// Extensions the core scanner is actually useful against. Skip everything
// else (markdown, images, lockfiles, etc.) so saving an unrelated file
// doesn't spawn a Python process for no reason.
const SCANNABLE_EXTENSIONS = new Set(['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.php', '.cs']);

/**
 * Neither checker.py's nor main.py's CLI prints machine-readable JSON on
 * this path (checker.py's --file mode prints a human-readable summary;
 * main.py prints progress text with emoji). Rather than change either
 * teammate's already-working, already-tested script to add a JSON mode
 * just for this, both are treated as "fire the script, then re-read
 * scan-state.json for the result" — the file on disk is the actual
 * contract here, not stdout. (Contrast with paste-guard/guard.py, which
 * genuinely needs a synchronous return value for the confirm-dialog gate,
 * so that one does print JSON — see pasteGuard.ts.)
 */
export function registerScanOrchestrator(context: vscode.ExtensionContext, diagnostics: FindingsDiagnostics) {
  const disposable = vscode.workspace.onDidSaveTextDocument((doc) => handleSave(doc, diagnostics));
  context.subscriptions.push(disposable);
}

async function handleSave(document: vscode.TextDocument, diagnostics: FindingsDiagnostics) {
  let workspaceRoot: string;
  try {
    workspaceRoot = getWorkspaceRoot();
  } catch {
    return; // no workspace open — nothing to do
  }

  const fileName = path.basename(document.uri.fsPath);
  const relativePath = path.relative(workspaceRoot, document.uri.fsPath);

  // Don't touch files outside the workspace (settings files, other projects, etc).
  if (relativePath.startsWith('..')) {
    return;
  }

  if (MANIFEST_FILES.has(fileName)) {
    await runPackageCheck(relativePath, workspaceRoot, diagnostics);
    return;
  }

  const ext = path.extname(fileName);
  if (!SCANNABLE_EXTENSIONS.has(ext)) {
    return;
  }

  await runCoreScan(relativePath, workspaceRoot, diagnostics);
}

async function runPackageCheck(relativePath: string, workspaceRoot: string, diagnostics: FindingsDiagnostics) {
  try {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: 'Ctrl+Alt+Delulu: checking packages…' },
      () =>
        runPython(getCheckerScriptPath(), {
          args: ['--file', relativePath, '--state', getStatePath()],
          cwd: workspaceRoot,
        })
    );
  } catch (err) {
    // Fail open: a broken/missing Python environment shouldn't block editing.
    console.error('Ctrl+Alt+Delulu: package check failed to run:', err);
  }
  await diagnostics.refresh();
}

async function runCoreScan(relativePath: string, workspaceRoot: string, diagnostics: FindingsDiagnostics) {
  try {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: 'Ctrl+Alt+Delulu: scanning…' },
      () => runPython(getMainScriptPath(), { args: [relativePath, '--state', getStatePath()], cwd: workspaceRoot })
    );
  } catch (err) {
    console.error('Ctrl+Alt+Delulu: scan failed to run:', err);
  }
  await diagnostics.refresh();
}
