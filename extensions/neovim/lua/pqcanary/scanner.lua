--[[
  PQCanary Neovim Scanner Engine
  Real-time Post-Quantum Cryptographic Analysis
  Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
--]]

local rules_module = require("pqcanary.rules")
local M = {}

-- Severity mapping to Neovim diagnostic severity
local SEVERITY_MAP = {
  CRITICAL = vim.diagnostic.severity.ERROR,
  HIGH = vim.diagnostic.severity.ERROR,
  MEDIUM = vim.diagnostic.severity.WARN,
  LOW = vim.diagnostic.severity.INFO,
  INFO = vim.diagnostic.severity.HINT,
}

local SEVERITY_SCORES = {
  CRITICAL = 25,
  HIGH = 15,
  MEDIUM = 5,
  LOW = 1,
  INFO = 0,
}

-- Compiled regex cache (vim.regex)
local compiled_cache = nil

function M.get_compiled_rules()
  if compiled_cache then
    return compiled_cache
  end

  compiled_cache = {}
  for _, rule in ipairs(rules_module.rules) do
    local ok, regex = pcall(vim.regex, rule.vim_pattern)
    if ok and regex then
      table.insert(compiled_cache, {
        rule = rule,
        regex = regex,
      })
    end
  end
  return compiled_cache
end

--- Scan text lines in a buffer and return diagnostic items
--- @param bufnr number Buffer number
--- @param lines table Array of line strings
--- @return table diagnostics Array of vim.diagnostic tables
--- @return table stats Summary stats (total, grade, critical, high, medium, low)
function M.scan_lines(bufnr, lines)
  local compiled = M.get_compiled_rules()
  local diagnostics = {}
  local penalty = 0
  local counts = {
    CRITICAL = 0,
    HIGH = 0,
    MEDIUM = 0,
    LOW = 0,
    INFO = 0,
  }

  for line_idx, line in ipairs(lines) do
    if #line > 0 and #line < 4096 then -- Skip excessively long minified lines for performance
      for _, item in ipairs(compiled) do
        local rule = item.rule
        local regex = item.regex

        local s, e = regex:match_str(line)
        while s and e do
          local start_col = s
          local end_col = e
          local matched_text = string.sub(line, start_col + 1, end_col)

          counts[rule.severity] = (counts[rule.severity] or 0) + 1
          penalty = penalty + (SEVERITY_SCORES[rule.severity] or 0)

          local severity_level = SEVERITY_MAP[rule.severity] or vim.diagnostic.severity.WARN
          local risk_prefix = rule.quantum_risk == "Safe" and "[PQ-SAFE]" or "[PQ-RISK: " .. rule.severity .. "]"

          local message = string.format(
            "%s %s (%s)\n• Issue: %s\n• Remediation: %s",
            risk_prefix,
            rule.name,
            rule.id,
            rule.description,
            rule.remediation
          )

          table.insert(diagnostics, {
            bufnr = bufnr,
            lnum = line_idx - 1,
            end_lnum = line_idx - 1,
            col = start_col,
            end_col = end_col,
            severity = severity_level,
            message = message,
            source = "PQCanary",
            code = rule.id,
            user_data = {
              rule = rule,
              matched_text = matched_text,
              remediation = rule.remediation,
              quantum_risk = rule.quantum_risk,
            },
          })

          -- Check for next match on the same line if end_col progressed
          if end_col > start_col then
            local rest_line = string.sub(line, end_col + 1)
            local next_s, next_e = regex:match_str(rest_line)
            if next_s and next_e then
              s = end_col + next_s
              e = end_col + next_e
            else
              s = nil
            end
          else
            s = nil
          end
        end
      end
    end
  end

  -- Calculate Security Health Grade
  local grade = "A+"
  if penalty >= 70 or counts.CRITICAL >= 3 then
    grade = "F"
  elseif penalty >= 45 or counts.CRITICAL >= 1 then
    grade = "D"
  elseif penalty >= 25 or counts.HIGH >= 2 then
    grade = "C"
  elseif penalty >= 10 or counts.HIGH >= 1 or counts.MEDIUM >= 2 then
    grade = "B"
  elseif penalty > 0 then
    grade = "A"
  end

  local stats = {
    total = #diagnostics,
    penalty = penalty,
    grade = grade,
    counts = counts,
  }

  return diagnostics, stats
end

--- Scan a buffer using the external PQCanary CLI if available
--- @param bufnr number Buffer number
--- @param file_path string Path to file
--- @param callback function Callback receiving (diagnostics, stats)
function M.scan_with_cli(bufnr, file_path, callback)
  if vim.fn.executable("pqcanary") ~= 1 then
    return false
  end

  local cmd = { "pqcanary", "scan", file_path, "--format", "json" }
  local output = {}

  vim.fn.jobstart(cmd, {
    stdout_buffered = true,
    on_stdout = function(_, data)
      if data then
        for _, line in ipairs(data) do
          if line ~= "" then
            table.insert(output, line)
          end
        end
      end
    end,
    on_exit = function(_, exit_code)
      if exit_code == 0 and #output > 0 then
        local raw_json = table.concat(output, "\n")
        local ok, parsed = pcall(vim.fn.json_decode, raw_json)
        if ok and parsed and parsed.findings then
          local diagnostics = {}
          for _, finding in ipairs(parsed.findings) do
            local sev = finding.severity or "MEDIUM"
            table.insert(diagnostics, {
              bufnr = bufnr,
              lnum = math.max(0, (finding.line or 1) - 1),
              end_lnum = math.max(0, (finding.line or 1) - 1),
              col = math.max(0, (finding.column or 1) - 1),
              end_col = math.max(0, (finding.column or 1) + 10),
              severity = SEVERITY_MAP[sev] or vim.diagnostic.severity.WARN,
              message = string.format(
                "[%s] %s: %s\nRemediation: %s",
                finding.rule_id or "PQCANARY",
                finding.rule_name or "Vulnerability",
                finding.description or "",
                finding.remediation or "Upgrade to Post-Quantum Standard (FIPS 203/204/205)"
              ),
              source = "PQCanary CLI",
              code = finding.rule_id,
            })
          end
          callback(diagnostics)
          return
        end
      end
      -- Fallback to lua scanner on failure
      local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
      local diag, stats = M.scan_lines(bufnr, lines)
      callback(diag, stats)
    end,
  })
  return true
end

return M
