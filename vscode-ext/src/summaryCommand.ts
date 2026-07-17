import * as vscode from 'vscode';
import { runPython } from './pythonRunner';
import { getGeneratorScriptPath, getStatePath, getSummaryHtmlPath, getWorkspaceRoot } from './config';

export function registerSummaryCommand(context: vscode.ExtensionContext) {
  const disposable = vscode.commands.registerCommand('ctrlAltDelulu.generateSummary', generateSummary);
  context.subscriptions.push(disposable);
}

async function generateSummary() {
  let workspaceRoot: string;
  try {
    workspaceRoot = getWorkspaceRoot();
  } catch (err) {
    vscode.window.showErrorMessage(err instanceof Error ? err.message : String(err));
    return;
  }

  const result = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'Ctrl+Alt+Delulu: generating project summary…' },
    () =>
      runPython(getGeneratorScriptPath(), {
        args: ['--state', getStatePath(), '--project', workspaceRoot, '--output', workspaceRoot],
        cwd: workspaceRoot,
      })
  );

  if (result.code !== 0) {
    vscode.window.showErrorMessage(`Summary generation failed: ${result.stderr || 'unknown error'}`);
    return;
  }

  // project-summary.html pulls in Google Fonts, a CDN script (the
  // "Download PDF" button), and inline <script> for the expandable
  // finding rows. A VS Code Webview's default CSP blocks all three of
  // those by design — rather than fight it with custom CSP injection,
  // just open the file the way generator.py's own console output already
  // tells the user to: in a real browser, where it all works as-built.
  await vscode.env.openExternal(vscode.Uri.file(getSummaryHtmlPath()));
}
