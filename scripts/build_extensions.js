const fs = require('fs');
const path = require('path');

// Ensure directories
['extensions/browser', 'extensions/vscode/src', 'extensions/neovim/lua/pqcanary', 'extensions/neovim/plugin'].forEach(dir => {
  fs.mkdirSync(dir, { recursive: true });
});

const tsContent = fs.readFileSync('web/src/lib/builtinRules.ts', 'utf8');

// Extract the array literal
const equalsBracketIdx = tsContent.indexOf('= [');
const startIdx = equalsBracketIdx !== -1 ? equalsBracketIdx + 2 : tsContent.indexOf('[');
const endIdx = tsContent.lastIndexOf(']');
const rulesArrayStr = tsContent.substring(startIdx, endIdx + 1);

// Generate browser rules.js
const browserRulesJs = `/**
 * PQCanary Rule Catalog for Browser Extension
 * Auto-generated from core/src/scanner/patterns.rs
 * Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
 */
const BUILTIN_RULES = ${rulesArrayStr};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BUILTIN_RULES };
}
`;
fs.writeFileSync('extensions/browser/rules.js', browserRulesJs);

// Generate VS Code rules.ts
const vscodeRulesTs = `/**
 * PQCanary Rule Catalog for VS Code Extension
 * Auto-generated from core/src/scanner/patterns.rs
 * Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
 */

export interface RuleDefinition {
  id: string;
  name: string;
  category: string;
  severity: string;
  quantum_risk: string;
  default_confidence: string;
  description: string;
  remediation: string;
  regex_pattern: string;
  tags: string[];
}

export const BUILTIN_RULES: RuleDefinition[] = ${rulesArrayStr};
`;
fs.writeFileSync('extensions/vscode/src/rules.ts', vscodeRulesTs);

// Generate Neovim rules.lua
function convertToVimRegex(raw) {
  let isCaseInsensitive = false;
  let p = raw;
  if (p.startsWith('(?i)')) {
    isCaseInsensitive = true;
    p = p.substring(4);
  }
  let vim = p
    .replace(/^\\b/, '<')
    .replace(/\\b$/, '>')
    .replace(/\\b\(/g, '<(')
    .replace(/\)\\b/g, ')>')
    .replace(/\\b/g, '(<|>)');
  const prefix = isCaseInsensitive ? '\\v\\c' : '\\v\\C';
  return prefix + vim;
}

const parsedRules = JSON.parse(rulesArrayStr);
const luaEntries = parsedRules.map(r => {
  const vimPattern = convertToVimRegex(r.regex_pattern);
  const tagsLua = '{ ' + (r.tags || []).map(t => JSON.stringify(t)).join(', ') + ' }';
  return `    {
      id = ${JSON.stringify(r.id)},
      name = ${JSON.stringify(r.name)},
      category = ${JSON.stringify(r.category)},
      severity = ${JSON.stringify(r.severity)},
      quantum_risk = ${JSON.stringify(r.quantum_risk)},
      default_confidence = ${JSON.stringify(r.default_confidence)},
      description = ${JSON.stringify(r.description)},
      remediation = ${JSON.stringify(r.remediation)},
      vim_pattern = ${JSON.stringify(vimPattern)},
      raw_pattern = ${JSON.stringify(r.regex_pattern)},
      tags = ${tagsLua}
    }`;
}).join(',\n');

const luaRulesContent = `-- PQCanary Rule Catalog for Neovim / Vim
-- Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
-- Auto-generated from core/src/scanner/patterns.rs

local M = {}

M.rules = {
${luaEntries}
}

return M
`;
fs.writeFileSync('extensions/neovim/lua/pqcanary/rules.lua', luaRulesContent);

console.log('Successfully generated rules for browser, vscode, and neovim extensions!');

