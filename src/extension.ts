import * as vscode from "vscode";
import { unsafePatterns } from "./patterns/unsafe-queries";
import { scanForUnsafePatterns, getSeverityColor } from "./utils/scanner";
import { Detection, Severity } from "./types";

// Diagnostic collection for storing the findings
let diagnosticCollection: vscode.DiagnosticCollection;

// Create a WebviewPanel to show details of vulnerabilities
let currentPanel: vscode.WebviewPanel | undefined = undefined;

export function activate(context: vscode.ExtensionContext) {
  console.log("SafeMongo extension is now active");

  // Create a diagnostic collection for MongoDB security issues
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("safemongo");
  context.subscriptions.push(diagnosticCollection);

  // Register code actions provider
  let disposable = vscode.languages.registerCodeActionsProvider(
    ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    new MongoSafeCodeActionProvider(),
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }
  );
  context.subscriptions.push(disposable);

  // Run on current open file when first activated
  if (vscode.window.activeTextEditor) {
    scanCurrentFile(vscode.window.activeTextEditor);
  }

  // Register the command to check the current file
  const checkCommand = vscode.commands.registerCommand(
    "safemongo.checkCurrentFile",
    () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanCurrentFile(editor);
      } else {
        vscode.window.showInformationMessage("No active editor found");
      }
    }
  );
  context.subscriptions.push(checkCommand);

  // Register document change events to continuously check for issues
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const editor = vscode.window.activeTextEditor;
      if (editor && event.document === editor.document) {
        scanCurrentFile(editor);
      }
    })
  );

  // Register document open events to check files when they're opened
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        scanCurrentFile(editor);
      }
    })
  );

  // Register a command to show vulnerability details
  const showDetailsCommand = vscode.commands.registerCommand(
    "safemongo.showVulnerabilityDetails",
    (detection: Detection) => {
      showVulnerabilityDetails(detection, context.extensionUri);
    }
  );
  context.subscriptions.push(showDetailsCommand);
}

/**
 * Scans the current file for unsafe MongoDB queries
 */
function scanCurrentFile(editor: vscode.TextEditor) {
  const document = editor.document;

  // Only scan JavaScript and TypeScript files
  if (
    document.languageId !== "javascript" &&
    document.languageId !== "typescript" &&
    document.languageId !== "javascriptreact" &&
    document.languageId !== "typescriptreact"
  ) {
    return;
  }

  const text = document.getText();
  const detections = scanForUnsafePatterns(
    text,
    unsafePatterns,
    document.fileName
  );

  updateDiagnostics(document, detections);
}

/**
 * Updates diagnostics with detected vulnerabilities
 */
function updateDiagnostics(
  document: vscode.TextDocument,
  detections: Detection[]
) {
  // Skip the pattern definition file itself
  if (
    document.fileName.includes("unsafe-queries.ts") ||
    document.fileName.includes("unsafe-queries.js")
  ) {
    diagnosticCollection.set(document.uri, []);
    return;
  }

  const diagnostics: vscode.Diagnostic[] = [];

  detections.forEach((detection) => {
    const line = document.lineAt(detection.lineNumber - 1);
    const range = new vscode.Range(
      detection.lineNumber - 1,
      0,
      detection.lineNumber - 1,
      line.text.length
    );

    const severity = getSeverityFromString(detection.pattern.severity);

    // Add severity icon
    const severityIcon = getSeverityIcon(detection.pattern.severity);

    const diagnostic = new vscode.Diagnostic(
      range,
      `${severityIcon} ${detection.pattern.name}: ${detection.pattern.description}`,
      severity
    );

    // Set more properties
    diagnostic.code = {
      value: detection.pattern.id,
      target: vscode.Uri.parse(detection.pattern.docUrl),
    };
    diagnostic.source = "SafeMongo";
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(document.uri, range),
        `Suggestion: ${detection.pattern.suggestion}`
      ),
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(document.uri, range),
        `Documentation: ${detection.pattern.docUrl}`
      ),
    ];

    // Add custom data to store with the diagnostic
    (diagnostic as any).detection = detection;

    diagnostics.push(diagnostic);
  });

  diagnosticCollection.set(document.uri, diagnostics);

  // Register code actions for these diagnostics
  if (!vscode.languages.registerCodeActionsProvider) {
    return;
  }

  vscode.languages.registerCodeActionsProvider(
    { language: "javascript" },
    new MongoSafeCodeActionProvider(),
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }
  );

  vscode.languages.registerCodeActionsProvider(
    { language: "typescript" },
    new MongoSafeCodeActionProvider(),
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }
  );
}

/**
 * Shows detailed information about a vulnerability
 */
function showVulnerabilityDetails(
  detection: Detection,
  extensionUri: vscode.Uri
) {
  if (currentPanel) {
    currentPanel.dispose();
  }

  currentPanel = vscode.window.createWebviewPanel(
    "mongoSecurityDetails",
    `MongoDB Security: ${detection.pattern.name}`,
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
    }
  );

  const pattern = detection.pattern;
  const severityColor = getSeverityColor(pattern.severity);

  currentPanel.webview.html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>MongoDB Security Issue</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
          padding: 20px;
          line-height: 1.5;
        }
        h1 {
          border-bottom: 1px solid #eee;
          padding-bottom: 10px;
          font-size: 24px;
        }
        h2 {
          font-size: 18px;
          margin-top: 20px;
        }
        .severity {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: bold;
          color: white;
          background-color: ${severityColor};
          margin-left: 10px;
          text-transform: uppercase;
        }
        pre {
          background-color: #f5f5f5;
          padding: 10px;
          border-radius: 4px;
          overflow-x: auto;
        }
        .bad-example {
          border-left: 4px solid #FF4D4F;
        }
        .good-example {
          border-left: 4px solid #52C41A;
        }
        .description {
          margin-bottom: 20px;
        }
        .doc-link {
          display: block;
          margin-top: 20px;
          padding: 10px;
          background-color: #f0f7ff;
          border-radius: 4px;
          text-decoration: none;
          color: #1890ff;
          border: 1px solid #d9e8ff;
        }
        .doc-link:hover {
          background-color: #e6f4ff;
        }
      </style>
    </head>
    <body>
      <h1>${pattern.name} <span class="severity">${pattern.severity}</span></h1>
      
      <div class="description">
        <p>${pattern.description}</p>
      </div>
      
      <h2>Line Found</h2>
      <pre class="bad-example">${detection.matchedText}</pre>
      
      <h2>Suggestion</h2>
      <p>${pattern.suggestion}</p>
      
      <h2>Vulnerable Example</h2>
      <pre class="bad-example">${pattern.example}</pre>
      
      <h2>Safe Example</h2>
      <pre class="good-example">${pattern.safeExample}</pre>

      <a href="${pattern.docUrl}" class="doc-link" target="_blank">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: sub; margin-right: 5px;">
          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
          <polyline points="15 3 21 3 21 9"></polyline>
          <line x1="10" y1="14" x2="21" y2="3"></line>
        </svg>
        MongoDB Documentation Reference
      </a>
    </body>
    </html>
  `;

  currentPanel.onDidDispose(() => {
    currentPanel = undefined;
  });
}

/**
 * Converts string severity to VSCode DiagnosticSeverity
 */
function getSeverityFromString(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Gets an icon to represent the severity level
 */
function getSeverityIcon(severity: Severity): string {
  switch (severity) {
    case "high":
      return "🛑"; // Red stop sign for high severity
    case "medium":
      return "⚠️"; // Warning triangle for medium severity
    case "low":
      return "ℹ️"; // Info symbol for low severity
    default:
      return "•"; // Default bullet point
  }
}

/**
 * Code action provider for MongoDB security fixes
 */
class MongoSafeCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] | undefined {
    const actions: vscode.CodeAction[] = [];

    // For each diagnostic, create a code action
    context.diagnostics.forEach((diagnostic) => {
      if (diagnostic.source !== "SafeMongo") {
        return;
      }

      const detection = (diagnostic as any).detection as Detection | undefined;
      if (!detection) {
        return;
      }

      // Create an action to show more details
      const action = new vscode.CodeAction(
        `Show details about this MongoDB security issue`,
        vscode.CodeActionKind.QuickFix
      );
      action.command = {
        command: "safemongo.showVulnerabilityDetails",
        title: "Show Vulnerability Details",
        arguments: [detection],
      };
      actions.push(action);
    });

    return actions;
  }
}

export function deactivate() {
  if (currentPanel) {
    currentPanel.dispose();
  }

  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
}
