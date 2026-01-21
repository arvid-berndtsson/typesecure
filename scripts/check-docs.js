#!/usr/bin/env node

/**
 * Script to check that all exported functions have JSDoc documentation.
 */

const fs = require("fs");
const path = require("path");
const ts = require("typescript");

const SRC_DIR = path.join(__dirname, "..", "src");
const EXCLUDED_FILES = ["index.ts", "testing.ts", "global.d.ts"];

/**
 * Check if a node has JSDoc comment.
 */
function hasJSDoc(node, sourceFile) {
  const fullText = sourceFile.getFullText();
  const nodeStart = node.getFullStart();
  const nodePos = sourceFile.getLineAndCharacterOfPosition(nodeStart);
  
  // Get text before the node
  const beforeNode = fullText.substring(0, nodeStart);
  const lines = beforeNode.split("\n");
  
  // Look backwards from the node for JSDoc comment
  // Start from the line before the node
  let foundJSDocStart = false;
  let inJSDocBlock = false;
  
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Check for end of JSDoc comment
    if (trimmed.includes("*/")) {
      inJSDocBlock = true;
      continue;
    }
    
    // Check for start of JSDoc comment
    if (trimmed.includes("/**")) {
      foundJSDocStart = true;
      return true;
    }
    
    // If we're in a JSDoc block, continue looking
    if (inJSDocBlock && (trimmed.startsWith("*") || trimmed === "")) {
      continue;
    }
    
    // If we hit non-comment, non-empty content, stop looking
    if (trimmed && !trimmed.startsWith("//") && !trimmed.startsWith("*") && !inJSDocBlock) {
      break;
    }
    
    // Reset if we're past the comment block
    if (inJSDocBlock && trimmed && !trimmed.startsWith("*") && !trimmed.includes("/**")) {
      inJSDocBlock = false;
    }
  }
  
  // Also check using TypeScript's getJSDocTags API
  const jsDocTags = ts.getJSDocTags(node);
  if (jsDocTags && jsDocTags.length > 0) {
    return true;
  }
  
  // Check for JSDoc comment nodes
  const jsDocComments = ts.getJSDocCommentsAndTags(node);
  if (jsDocComments && jsDocComments.length > 0) {
    return true;
  }
  
  return false;
}

/**
 * Check TypeScript file for exported functions without JSDoc.
 */
function checkFile(filePath) {
  const content = fs.readFileSync(filePath, "utf-8");
  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    true
  );
  
  const issues = [];
  
  function visit(node) {
    // Check for exported function declarations
    if (
      ts.isFunctionDeclaration(node) &&
      node.name &&
      (ts.getModifiers(node)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ||
        node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword))
    ) {
      if (!hasJSDoc(node, sourceFile)) {
        const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        issues.push({
          file: path.relative(SRC_DIR, filePath),
          line,
          function: node.name.text,
          type: "function declaration",
        });
      }
    }
    
    // Check for exported variable declarations that are functions
    if (ts.isVariableStatement(node)) {
      const isExported = ts.getModifiers(node)?.some(
        (m) => m.kind === ts.SyntaxKind.ExportKeyword
      ) || node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
      
      if (isExported) {
        node.declarationList.declarations.forEach((decl) => {
          if (
            decl.name &&
            ts.isIdentifier(decl.name) &&
            (ts.isArrowFunction(decl.initializer) ||
              ts.isFunctionExpression(decl.initializer))
          ) {
            if (!hasJSDoc(node, sourceFile)) {
              const line =
                sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
              issues.push({
                file: path.relative(SRC_DIR, filePath),
                line,
                function: decl.name.text,
                type: "exported function",
              });
            }
          }
        });
      }
    }
    
    ts.forEachChild(node, visit);
  }
  
  visit(sourceFile);
  return issues;
}

/**
 * Recursively find all TypeScript files in src directory.
 */
function findTSFiles(dir) {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      files.push(...findTSFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) {
      if (!EXCLUDED_FILES.includes(entry.name)) {
        files.push(fullPath);
      }
    }
  }
  
  return files;
}

/**
 * Main function.
 */
function main() {
  const files = findTSFiles(SRC_DIR);
  const allIssues = [];
  
  for (const file of files) {
    const issues = checkFile(file);
    allIssues.push(...issues);
  }
  
  if (allIssues.length > 0) {
    console.error("❌ Found exported functions without JSDoc documentation:\n");
    for (const issue of allIssues) {
      console.error(`  ${issue.file}:${issue.line} - ${issue.function}()`);
    }
    console.error(`\nTotal: ${allIssues.length} function(s) missing documentation`);
    process.exit(1);
  } else {
    console.log("✅ All exported functions have JSDoc documentation");
    process.exit(0);
  }
}

main();
