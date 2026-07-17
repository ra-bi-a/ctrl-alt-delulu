import * as vscode from 'vscode';
import * as path from 'path';

/**
 * This extension is designed to run with the ctrl-alt-delulu repo itself
 * open as the VS Code workspace — every Python script (main.py,
 * pkg-checker/checker.py, paste-guard/guard.py, summary/generator.py) and
 * scan-state.json already assume they live at / relative to "the project
 * root" (see each script's own docstring). So "the workspace folder" and
 * "the repo root" are the same folder here, and every path below is
 * resolved from it — NOT from wherever the compiled extension.js happens
 * to sit. That matters if this extension ever gets bundled/installed
 * separately from the repo it's meant to scan.
 */
function getWorkspaceRoot(): string {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    throw new Error(
      'Ctrl+Alt+Delulu: open the project folder (the one containing main.py and scan-state.json) as your VS Code workspace first.'
    );
  }
  // Multi-root workspaces aren't handled specially — first folder wins.
  // Fine for a hackathon demo; would need real thought for anything bigger.
  return folders[0].uri.fsPath;
}

export function getStatePath(): string {
  return path.join(getWorkspaceRoot(), 'scan-state.json');
}

export function getMainScriptPath(): string {
  return path.join(getWorkspaceRoot(), 'main.py');
}

export function getCheckerScriptPath(): string {
  return path.join(getWorkspaceRoot(), 'pkg-checker', 'checker.py');
}

export function getGuardScriptPath(): string {
  return path.join(getWorkspaceRoot(), 'paste-guard', 'guard.py');
}

export function getGeneratorScriptPath(): string {
  return path.join(getWorkspaceRoot(), 'summary', 'generator.py');
}

export function getSummaryHtmlPath(): string {
  return path.join(getWorkspaceRoot(), 'project-summary.html');
}

export { getWorkspaceRoot };
