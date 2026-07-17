import * as vscode from 'vscode';
import { FindingsDiagnostics } from './diagnostics';
import { registerScanOrchestrator } from './scanOrchestrator';
import { registerPasteGuard } from './pasteGuard';
import { registerSummaryCommand } from './summaryCommand';

export function activate(context: vscode.ExtensionContext) {
  const diagnostics = new FindingsDiagnostics(context);

  registerScanOrchestrator(context, diagnostics);
  registerPasteGuard(context, diagnostics);
  registerSummaryCommand(context);

  // Show whatever's already in scan-state.json immediately when a
  // workspace opens, rather than waiting for the first save.
  diagnostics.refresh();
}

export function deactivate(): void {
  // Nothing to clean up by hand — the DiagnosticCollection is disposed
  // automatically via context.subscriptions.
}
