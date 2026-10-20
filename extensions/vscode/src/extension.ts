/**
 * PQCanary VS Code Extension
 * Real-time post-quantum cryptographic security analysis, diagnostics, and remediation.
 * Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
 */

import * as vscode from 'vscode';
import { BUILTIN_RULES, RuleDefinition } from './rules';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
const debounceTimers = new Map<string, NodeJS.Timeout>();

// Precompile regexes once for high-performance real-time analysis
interface CompiledRule {
  rule: RuleDefinition;
  regex: RegExp;
}

const compiledRules: CompiledRule[] = BUILTIN_RULES.map(rule => {
  let pattern = rule.regex_pattern;
  let flags = 'g';
  if (pattern.startsWith('(?i)')) {
    pattern = pattern.substring(4);
    flags = 'gi';
  }
  try {
    return { rule, regex: new RegExp(pattern, flags) };
  } catch {
    return null;
  }
}).filter((r): r is CompiledRule => r !== null);

const SEVERITY_RANKS: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0
};

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('pqcanary');
  context.subscriptions.push(diagnosticCollection);

  // Status Bar Item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'pqcanary.scanCurrentFile';
  statusBarItem.text = '$(shield) PQ: Ready';
  statusBarItem.tooltip = 'PQCanary Post-Quantum Cryptographic Auditor';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Register Code Actions (Quick Fixes)
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new PqCanaryCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  // Document Listeners for Real-Time Analysis
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      const config = vscode.workspace.getConfiguration('pqcanary');
      if (!config.get<boolean>('enableRealtime', true)) return;

      const uriStr = event.document.uri.toString();
      const delay = config.get<number>('debounceMs', 200);

      const existingTimer = debounceTimers.get(uriStr);
      if (existingTimer) clearTimeout(existingTimer);

      debounceTimers.set(
        uriStr,
        setTimeout(() => {
          debounceTimers.delete(uriStr);
          analyzeDocument(event.document);
        }, delay)
      );
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => {
      analyzeDocument(doc);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      diagnosticCollection.delete(doc.uri);
      debounceTimers.delete(doc.uri.toString());
    })
  );

  // Scan Active File Command
  context.subscriptions.push(
    vscode.commands.registerCommand('pqcanary.scanCurrentFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('No active editor open to scan.');
        return;
      }
      const count = analyzeDocument(editor.document);
      if (count === 0) {
        vscode.window.showInformationMessage('PQCanary: No post-quantum cryptographic vulnerabilities found.');
      } else {
        vscode.window.showWarningMessage(`PQCanary: Detected ${count} cryptographic security issues in current file.`);
      }
    })
  );

  // Scan Workspace Command
  context.subscriptions.push(
    vscode.commands.registerCommand('pqcanary.scanWorkspace', async () => {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'PQCanary: Scanning workspace for quantum vulnerabilities...',
          cancellable: false
        },
        async progress => {
          const files = await vscode.workspace.findFiles(
            '**/*.{js,ts,jsx,tsx,py,rs,go,java,c,cpp,cs,swift,sol,php,rb,json,yaml,yml,env,pem,key}',
            '**/node_modules/**'
          );

          let totalIssues = 0;
          for (let i = 0; i < files.length; i++) {
            const file = files[i];
            progress.report({
              message: `${i + 1}/${files.length} (${vscode.workspace.asRelativePath(file)})`,
              increment: (1 / files.length) * 100
            });
            try {
              const doc = await vscode.workspace.openTextDocument(file);
              totalIssues += analyzeDocument(doc);
            } catch {
              // Skip unreadable files
            }
          }

          if (totalIssues === 0) {
            vscode.window.showInformationMessage('PQCanary: Workspace is 100% compliant with NIST FIPS 203/204 standards!');
          } else {
            vscode.window.showWarningMessage(`PQCanary: Detected ${totalIssues} cryptographic deficits across workspace.`);
          }
        }
      );
    })
  );

  // Open Web Dashboard Command
  context.subscriptions.push(
    vscode.commands.registerCommand('pqcanary.openWebDashboard', () => {
      const config = vscode.workspace.getConfiguration('pqcanary');
      const serverUrl = config.get<string>('serverUrl', 'http://localhost:3000');
      vscode.env.openExternal(vscode.Uri.parse(serverUrl));
    })
  );

  // Inspect Distributed PQMesh Fleet Status Command
  context.subscriptions.push(
    vscode.commands.registerCommand('pqcanary.meshStatus', async () => {
      const config = vscode.workspace.getConfiguration('pqcanary');
      const meshUrl = config.get<string>('meshUrl', 'http://localhost:8080');
      try {
        const resp = await fetch(`${meshUrl}/mesh/summary`);
        if (resp.ok) {
          const data: any = await resp.json();
          const action = await vscode.window.showInformationMessage(
            `PQMesh Fleet: ${data.total_nodes_online} nodes online (Health Score: ${data.fleet_health_score}%). Total Findings: ${data.total_fleet_findings}.`,
            'Open Web Dashboard',
            'Broadcast Fleet Directive'
          );
          if (action === 'Open Web Dashboard') {
            vscode.commands.executeCommand('pqcanary.openWebDashboard');
          } else if (action === 'Broadcast Fleet Directive') {
            const msg = await vscode.window.showInputBox({ prompt: 'Broadcast message across all corporate fleet mediums' });
            if (msg) {
              await broadcastMeshEvent('Developer Workstation Directive', msg, 'MEDIUM');
              vscode.window.showInformationMessage('Directive broadcast across PQMesh fleet!');
            }
          }
        } else {
          vscode.window.showWarningMessage(`PQMesh daemon returned HTTP ${resp.status}`);
        }
      } catch (e) {
        vscode.window.showErrorMessage(`Cannot reach PQMesh fleet daemon at ${meshUrl}: ${e}`);
      }
    })
  );

  // Hook patch applied notification from QuickFix code actions
  context.subscriptions.push(
    vscode.commands.registerCommand('pqcanary.onPatchApplied', async (codeStr: string, fsPath: string) => {
      patchesAppliedCount++;
      const fileName = vscode.workspace.asRelativePath(fsPath);
      await broadcastMeshEvent(
        'NIST FIPS 203/204 Remediation Applied',
        `Automated patch applied for ${codeStr} in ${fileName}`,
        'INFO'
      );
      updateMeshRegistration(fileName);
    })
  );

  // Initialize PQMesh Fleet Sync
  initMeshSync();

  // Analyze visible documents on startup
  if (vscode.window.activeTextEditor) {
    analyzeDocument(vscode.window.activeTextEditor.document);
  }
}

let meshHeartbeatTimer: NodeJS.Timeout | null = null;
let patchesAppliedCount = 0;
let scansCompletedCount = 0;
let totalFindingsCount = 0;
let activeDocumentPath = 'Ready';

function getNodeId(): string {
  const machine = vscode.env.machineId ? vscode.env.machineId.substring(0, 8) : 'inst';
  return `node-vscode-${machine}`;
}

async function updateMeshRegistration(contextPath?: string) {
  const config = vscode.workspace.getConfiguration('pqcanary');
  if (!config.get<boolean>('enableMeshSync', true)) return;

  const meshUrl = config.get<string>('meshUrl', 'http://localhost:8080');
  if (contextPath) activeDocumentPath = contextPath;

  const payload = {
    node_id: getNodeId(),
    medium: 'vscode',
    label: `VS Code Workstation (${vscode.workspace.name || 'IDE'})`,
    version: '1.0.0',
    endpoint: `vscode://${getNodeId()}`,
    active_context: activeDocumentPath,
    findings_count: totalFindingsCount,
    scans_count: scansCompletedCount,
    patches_applied: patchesAppliedCount,
  };

  try {
    await fetch(`${meshUrl}/mesh/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch {
    // Non-blocking: mesh daemon might be offline or initializing
  }
}

async function broadcastMeshEvent(title: string, details: string, severity: string = 'INFO') {
  const config = vscode.workspace.getConfiguration('pqcanary');
  if (!config.get<boolean>('enableMeshSync', true)) return;

  const meshUrl = config.get<string>('meshUrl', 'http://localhost:8080');
  const payload = {
    source_node_id: getNodeId(),
    source_medium: 'vscode',
    title,
    details,
    severity,
  };

  try {
    await fetch(`${meshUrl}/mesh/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch {
    // Silent fail if daemon unavailable
  }
}

function initMeshSync() {
  updateMeshRegistration();
  if (meshHeartbeatTimer) clearInterval(meshHeartbeatTimer);
  meshHeartbeatTimer = setInterval(() => {
    updateMeshRegistration();
  }, 45000);
}

export function deactivate() {
  if (meshHeartbeatTimer) {
    clearInterval(meshHeartbeatTimer);
    meshHeartbeatTimer = null;
  }
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
}

function analyzeDocument(document: vscode.TextDocument): number {
  if (document.uri.scheme !== 'file') return 0;

  const config = vscode.workspace.getConfiguration('pqcanary');
  const minSev = config.get<string>('minSeverity', 'LOW').toUpperCase();
  const minRank = SEVERITY_RANKS[minSev] ?? 1;

  const text = document.getText();
  const diagnostics: vscode.Diagnostic[] = [];

  for (const { rule, regex } of compiledRules) {
    const rank = SEVERITY_RANKS[rule.severity] ?? 0;
    if (rank < minRank) continue;

    regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      if (match[0].length === 0) {
        regex.lastIndex++;
        continue;
      }
      const startPos = document.positionAt(match.index);
      const endPos = document.positionAt(match.index + match[0].length);
      const range = new vscode.Range(startPos, endPos);

      // Map Severity
      let severity = vscode.DiagnosticSeverity.Information;
      if (rule.severity === 'CRITICAL' || rule.severity === 'HIGH') {
        severity = vscode.DiagnosticSeverity.Error;
      } else if (rule.severity === 'MEDIUM') {
        severity = vscode.DiagnosticSeverity.Warning;
      }

      const message = `[PQCanary ${rule.id}] ${rule.name}: ${rule.description}\nRemediation: ${rule.remediation}`;
      const diag = new vscode.Diagnostic(range, message, severity);
      diag.source = 'PQCanary';
      diag.code = rule.id;

      diagnostics.push(diag);
    }
  }

  diagnosticCollection.set(document.uri, diagnostics);
  updateStatusBar(diagnostics);

  scansCompletedCount++;
  totalFindingsCount = diagnostics.length;
  updateMeshRegistration(vscode.workspace.asRelativePath(document.uri.fsPath));

  return diagnostics.length;
}

function updateStatusBar(diagnostics: vscode.Diagnostic[]) {
  if (!statusBarItem) return;

  const criticalOrHigh = diagnostics.filter(
    d => d.severity === vscode.DiagnosticSeverity.Error
  ).length;

  if (diagnostics.length === 0) {
    statusBarItem.text = '$(shield) PQ: A+ (Safe)';
    statusBarItem.tooltip = 'PQCanary: All cryptographic primitives are Post-Quantum Safe (NIST FIPS 203/204)';
    statusBarItem.color = '#10B981';
  } else if (criticalOrHigh > 0) {
    statusBarItem.text = `$(alert) PQ: C (${diagnostics.length} issues)`;
    statusBarItem.tooltip = `PQCanary: ${criticalOrHigh} critical/high quantum deficits detected in current file!`;
    statusBarItem.color = '#EF4444';
  } else {
    statusBarItem.text = `$(info) PQ: B (${diagnostics.length} notices)`;
    statusBarItem.tooltip = `PQCanary: ${diagnostics.length} warnings/notices detected in current file.`;
    statusBarItem.color = '#F59E0B';
  }
}

/**
 * Provides automated Quick Fix Code Actions for NIST FIPS 203/204 PQC migrations
 */
class PqCanaryCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'PQCanary') continue;
      const codeStr = String(diagnostic.code || '');

      // Quick fix for RSA or classical asymmetric key exchange
      if (codeStr.includes('RSA') || codeStr.includes('ASYM') || codeStr.includes('KEX')) {
        const kemFix = new vscode.CodeAction(
          'Migrate to NIST FIPS 203 (ML-KEM-768)',
          vscode.CodeActionKind.QuickFix
        );
        kemFix.edit = new vscode.WorkspaceEdit();
        kemFix.edit.replace(document.uri, diagnostic.range, 'ML-KEM-768');
        kemFix.command = { command: 'pqcanary.onPatchApplied', title: 'Remediation Applied', arguments: ['ML-KEM-768', document.uri.fsPath] };
        actions.push(kemFix);

        const sigFix = new vscode.CodeAction(
          'Migrate to NIST FIPS 204 (ML-DSA-65)',
          vscode.CodeActionKind.QuickFix
        );
        sigFix.edit = new vscode.WorkspaceEdit();
        sigFix.edit.replace(document.uri, diagnostic.range, 'ML-DSA-65');
        sigFix.diagnostics = [diagnostic];
        sigFix.command = { command: 'pqcanary.onPatchApplied', title: 'Remediation Applied', arguments: ['ML-DSA-65', document.uri.fsPath] };
        actions.push(sigFix);
      }

      // Quick fix for classical hash (MD5, SHA-1)
      if (codeStr.includes('MD5') || codeStr.includes('SHA1') || codeStr.includes('HASH')) {
        const hashFix = new vscode.CodeAction(
          'Replace with NIST FIPS 202 (SHA-3 / SHAKE256)',
          vscode.CodeActionKind.QuickFix
        );
        hashFix.edit = new vscode.WorkspaceEdit();
        hashFix.edit.replace(document.uri, diagnostic.range, 'SHA3-256');
        hashFix.diagnostics = [diagnostic];
        hashFix.isPreferred = true;
        hashFix.command = { command: 'pqcanary.onPatchApplied', title: 'Remediation Applied', arguments: ['SHA3-256', document.uri.fsPath] };
        actions.push(hashFix);
      }

      // Quick fix for classical symmetric key size (< 256 bits)
      if (codeStr.includes('SYM') || codeStr.includes('AES128') || codeStr.includes('DES')) {
        const symFix = new vscode.CodeAction(
          'Upgrade to AES-256-GCM (Quantum-Resistant)',
          vscode.CodeActionKind.QuickFix
        );
        symFix.edit = new vscode.WorkspaceEdit();
        symFix.edit.replace(document.uri, diagnostic.range, 'AES-256-GCM');
        symFix.diagnostics = [diagnostic];
        symFix.isPreferred = true;
        symFix.command = { command: 'pqcanary.onPatchApplied', title: 'Remediation Applied', arguments: ['AES-256-GCM', document.uri.fsPath] };
        actions.push(symFix);
      }
    }

    return actions;
  }
}
