--[[
  PQCanary Neovim Extension
  Real-time Post-Quantum Cryptographic Linting, Quickfix, and Diagnostics
  Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
--]]

local scanner = require("pqcanary.scanner")
local quickfix = require("pqcanary.quickfix")

local M = {}

-- Diagnostic namespace
M.namespace = vim.diagnostic.create_namespace("pqcanary")

-- Default configuration
M.config = {
  enable_realtime = true,
  debounce_ms = 200,
  virtual_text = true,
  signs = true,
  underline = true,
  min_severity = "INFO",
  auto_quickfix = false,
  prefer_cli = false,
  mesh_url = "http://localhost:8080",
  enable_mesh_sync = true,
}

-- Per-buffer stats cache
M.buffer_stats = {}
local debounce_timers = {}
local is_enabled = true

-- Setup highlight groups and signs
local function setup_highlights()
  vim.api.nvim_set_hl(0, "PQCanaryCritical", { fg = "#ff4d4f", bold = true, default = true })
  vim.api.nvim_set_hl(0, "PQCanaryHigh", { fg = "#fa8c16", bold = true, default = true })
  vim.api.nvim_set_hl(0, "PQCanaryMedium", { fg = "#fadb14", default = true })
  vim.api.nvim_set_hl(0, "PQCanarySafe", { fg = "#52c41a", default = true })

  if vim.fn.has("nvim-0.6") == 1 then
    local signs = {
      { name = "PQCanarySignError", text = "󰞏", hl = "PQCanaryCritical" },
      { name = "PQCanarySignWarn", text = "▲", hl = "PQCanaryHigh" },
      { name = "PQCanarySignInfo", text = "ℹ", hl = "PQCanaryMedium" },
      { name = "PQCanarySignHint", text = "󰌵", hl = "PQCanarySafe" },
    }
    for _, sign in ipairs(signs) do
      vim.fn.sign_define(sign.name, { text = sign.text, texthl = sign.hl, numhl = "" })
    end
  end
end

--- Scan a buffer and update diagnostics
--- @param bufnr number Buffer number (0 for current)
--- @param force boolean Force scan even if realtime is disabled
function M.scan_buffer(bufnr, force)
  if not is_enabled and not force then
    return
  end

  bufnr = (bufnr == 0 or bufnr == nil) and vim.api.nvim_get_current_buf() or bufnr
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end

  -- Check if buffer is a normal file
  local buftype = vim.api.nvim_buf_get_option(bufnr, "buftype")
  if buftype ~= "" then
    return
  end

  local file_path = vim.api.nvim_buf_get_name(bufnr)

  local function apply_results(diagnostics, stats)
    vim.diagnostic.set(M.namespace, bufnr, diagnostics, {
      virtual_text = M.config.virtual_text,
      signs = M.config.signs,
      underline = M.config.underline,
    })
    if stats then
      M.buffer_stats[bufnr] = stats
    end
    if M.config.auto_quickfix and #diagnostics > 0 then
      quickfix.populate_quickfix(diagnostics, "PQCanary Findings", false)
    end
  end

  if M.config.prefer_cli and file_path ~= "" then
    local dispatched = scanner.scan_with_cli(bufnr, file_path, function(diagnostics, stats)
      apply_results(diagnostics, stats)
    end)
    if dispatched then
      return
    end
  end

  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local diagnostics, stats = scanner.scan_lines(bufnr, lines)
  apply_results(diagnostics, stats)
end

--- Debounced scan for real-time typing events
--- @param bufnr number
local function schedule_scan(bufnr)
  if not is_enabled or not M.config.enable_realtime then
    return
  end

  if debounce_timers[bufnr] then
    debounce_timers[bufnr]:stop()
    debounce_timers[bufnr]:close()
    debounce_timers[bufnr] = nil
  end

  local timer = (vim.uv or vim.loop).new_timer()
  debounce_timers[bufnr] = timer

  timer:start(
    M.config.debounce_ms,
    0,
    vim.schedule_wrap(function()
      if debounce_timers[bufnr] == timer then
        debounce_timers[bufnr] = nil
        timer:stop()
        timer:close()
        M.scan_buffer(bufnr)
      end
    end)
  )
end

--- Apply automated PQC remediation to the diagnostic under cursor
function M.apply_fix()
  local bufnr = vim.api.nvim_get_current_buf()
  local cursor = vim.api.nvim_win_get_cursor(0)
  local cur_line_idx = cursor[1] - 1
  local cur_col = cursor[2]

  local diagnostics = vim.diagnostic.get(bufnr, { namespace = M.namespace, lnum = cur_line_idx })
  if #diagnostics == 0 then
    vim.notify("PQCanary: No quantum vulnerability diagnostic found on this line.", vim.log.levels.INFO)
    return
  end

  local diag = diagnostics[1]
  local user_data = diag.user_data or {}
  local rule = user_data.rule
  local matched_text = user_data.matched_text

  if not rule or not matched_text then
    vim.notify("PQCanary: Diagnostic cannot be automatically remediated.", vim.log.levels.WARN)
    return
  end

  -- Determine recommended replacement based on NIST PQC standards
  local replacement = nil
  local upper_text = string.upper(matched_text)

  if string.find(upper_text, "RSA") then
    replacement = "ML-KEM-768"
  elseif string.find(upper_text, "ECDSA") or string.find(upper_text, "ED25519") or string.find(upper_text, "SECP") then
    replacement = "ML-DSA-65"
  elseif string.find(upper_text, "X25519") or string.find(upper_text, "DH") or string.find(upper_text, "ECDH") then
    replacement = "X25519MLKEM768"
  elseif string.find(upper_text, "SHA1") or string.find(upper_text, "MD5") or string.find(upper_text, "SHA-1") then
    replacement = "SHA3-256"
  elseif string.find(upper_text, "KYBER") then
    replacement = "ML-KEM-768"
  elseif string.find(upper_text, "DILITHIUM") then
    replacement = "ML-DSA-65"
  else
    replacement = "ML-KEM-768"
  end

  local line = vim.api.nvim_buf_get_lines(bufnr, cur_line_idx, cur_line_idx + 1, false)[1] or ""
  local new_line = string.sub(line, 1, diag.col) .. replacement .. string.sub(line, diag.end_col + 1)

  vim.api.nvim_buf_set_lines(bufnr, cur_line_idx, cur_line_idx + 1, false, { new_line })
  vim.notify(
    string.format("PQCanary: Replaced '%s' with '%s' (NIST FIPS PQC Compliant)", matched_text, replacement),
    vim.log.levels.INFO
  )

  -- Re-scan immediately
  M.scan_buffer(bufnr, true)
end

--- Display security posture and health grade for current buffer
function M.status_info()
  local bufnr = vim.api.nvim_get_current_buf()
  local stats = M.buffer_stats[bufnr]
  if not stats then
    M.scan_buffer(bufnr, true)
    stats = M.buffer_stats[bufnr]
  end

  if not stats then
    vim.notify("PQCanary: No scan data available for current buffer.", vim.log.levels.INFO)
    return
  end

  local lines = {
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    string.format(" 🛡️  PQCanary Quantum Security Posture: Grade %s", stats.grade),
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    string.format(" Total Issues Found : %d", stats.total),
    string.format(" • Critical (RSA/ECC) : %d", stats.counts.CRITICAL or 0),
    string.format(" • High (Vulnerable)  : %d", stats.counts.HIGH or 0),
    string.format(" • Medium (Deprec.)   : %d", stats.counts.MEDIUM or 0),
    string.format(" • Low (Warning)      : %d", stats.counts.LOW or 0),
    string.format(" • Safe (PQC Ready)   : %d", stats.counts.INFO or 0),
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    " Recommendation: Run :PQCanaryFix on highlighted lines or :PQCanaryQuickfix",
  }

  vim.notify(table.concat(lines, "\n"), vim.log.levels.INFO)
end

--- Get status string for statusline integrations (lualine, heirline, etc.)
--- @param bufnr number
--- @return string Status summary
function M.get_status(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local stats = M.buffer_stats[bufnr]
  if not stats or stats.total == 0 then
    return "🛡️ PQ: A+"
  end
  return string.format("🛡️ PQ: %s (%d vuln)", stats.grade, (stats.counts.CRITICAL or 0) + (stats.counts.HIGH or 0))
end

--- Toggle PQCanary active state
function M.toggle()
  is_enabled = not is_enabled
  local bufnr = vim.api.nvim_get_current_buf()
  if not is_enabled then
    vim.diagnostic.reset(M.namespace, bufnr)
    vim.notify("PQCanary: Real-time analysis disabled.", vim.log.levels.WARN)
  else
    vim.notify("PQCanary: Real-time analysis enabled.", vim.log.levels.INFO)
    M.scan_buffer(bufnr, true)
  end
end

local mesh_heartbeat_timer = nil
local nvim_scans_count = 0
local nvim_patches_count = 0

--- Synchronize node state and findings with the PQMesh fleet bus
--- @param active_context string|nil
function M.sync_mesh(active_context)
  if not M.config.enable_mesh_sync then return end
  local ctx = active_context or vim.fn.expand("%:t")
  if ctx == "" then ctx = "Neovim Active Buffer" end

  local total_findings = 0
  for _, stats in pairs(M.buffer_stats) do
    if stats and stats.counts then
      total_findings = total_findings + (stats.counts.CRITICAL or 0) + (stats.counts.HIGH or 0) + (stats.counts.MEDIUM or 0)
    end
  end

  local payload = string.format(
    '{"node_id":"node-neovim-wkst","medium":"neovim","label":"Neovim Editor","version":"1.0.0","endpoint":"nvim://localhost","active_context":"%s","findings_count":%d,"scans_count":%d,"patches_applied":%d}',
    ctx:gsub('"', '\\"'),
    total_findings,
    nvim_scans_count,
    nvim_patches_count
  )

  local cmd = { "curl", "-s", "-X", "POST", M.config.mesh_url .. "/mesh/register", "-H", "Content-Type: application/json", "-d", payload }
  if vim.fn.executable("curl") == 1 then
    vim.fn.jobstart(cmd, { detach = true })
  end
end

--- Broadcast a cryptographic alert or patch event to the fleet bus
--- @param title string
--- @param details string
--- @param severity string|nil
function M.broadcast_mesh_event(title, details, severity)
  if not M.config.enable_mesh_sync then return end
  local sev = severity or "INFO"
  local payload = string.format(
    '{"source_node_id":"node-neovim-wkst","source_medium":"neovim","title":"%s","details":"%s","severity":"%s"}',
    title:gsub('"', '\\"'),
    details:gsub('"', '\\"'),
    sev
  )
  local cmd = { "curl", "-s", "-X", "POST", M.config.mesh_url .. "/mesh/event", "-H", "Content-Type: application/json", "-d", payload }
  if vim.fn.executable("curl") == 1 then
    vim.fn.jobstart(cmd, { detach = true })
  end
end

--- Query PQMesh fleet status and notify in editor
function M.mesh_status()
  if vim.fn.executable("curl") ~= 1 then
    vim.notify("PQCanary: curl not found to query PQMesh fleet.", vim.log.levels.WARN)
    return
  end
  local cmd = { "curl", "-s", M.config.mesh_url .. "/mesh/summary" }
  vim.fn.jobstart(cmd, {
    stdout_buffered = true,
    on_stdout = function(_, data)
      local raw = table.concat(data, "")
      if raw and raw ~= "" then
        local ok, decoded = pcall(vim.json.decode, raw)
        if ok and decoded then
          vim.notify(
            string.format("PQMesh Fleet: %d nodes online (Health: %.1f%%)\nTotal Findings: %d | Critical: %d",
              decoded.total_nodes_online or 0,
              decoded.fleet_health_score or 100,
              decoded.total_fleet_findings or 0,
              decoded.critical_findings_count or 0),
            vim.log.levels.INFO,
            { title = "PQCanary Fleet Mesh" }
          )
          return
        end
      end
      vim.notify("PQMesh daemon unreachable at " .. M.config.mesh_url, vim.log.levels.WARN)
    end
  })
end

--- Initialize PQCanary Neovim Plugin
--- @param opts table Configuration overrides
function M.setup(opts)
  if opts then
    M.config = vim.tbl_deep_extend("force", M.config, opts)
  end

  setup_highlights()

  -- Create User Commands
  vim.api.nvim_create_user_command("PQCanaryScan", function()
    M.scan_buffer(0, true)
    vim.notify("PQCanary: Buffer scan complete.", vim.log.levels.INFO)
  end, { desc = "Scan current buffer for post-quantum security issues" })

  vim.api.nvim_create_user_command("PQCanaryToggle", function()
    M.toggle()
  end, { desc = "Toggle PQCanary real-time analysis" })

  vim.api.nvim_create_user_command("PQCanaryQuickfix", function()
    local bufnr = vim.api.nvim_get_current_buf()
    local diags = vim.diagnostic.get(bufnr, { namespace = M.namespace })
    if #diags == 0 then
      M.scan_buffer(bufnr, true)
      diags = vim.diagnostic.get(bufnr, { namespace = M.namespace })
    end
    quickfix.populate_quickfix(diags, "PQCanary Quantum Audit", true)
  end, { desc = "Populate Quickfix list with quantum issues" })

  vim.api.nvim_create_user_command("PQCanaryFix", function()
    M.apply_fix()
  end, { desc = "Apply automated post-quantum remediation under cursor" })

  vim.api.nvim_create_user_command("PQCanaryStatus", function()
    M.status_info()
  end, { desc = "Show quantum security health grade" })

  vim.api.nvim_create_user_command("PQCanaryMesh", function()
    M.mesh_status()
  end, { desc = "Inspect distributed PQMesh fleet status across all mediums" })

  -- Start periodic PQMesh fleet heartbeat
  if M.config.enable_mesh_sync then
    M.sync_mesh("Neovim Editor Online")
    local uv = vim.uv or vim.loop
    if uv and uv.new_timer then
      mesh_heartbeat_timer = uv.new_timer()
      mesh_heartbeat_timer:start(45000, 45000, vim.schedule_wrap(function()
        M.sync_mesh()
      end))
    end
  end

  -- Set up Autocommands
  local group = vim.api.nvim_create_augroup("PQCanaryAutoGroup", { clear = true })

  vim.api.nvim_create_autocmd({ "BufReadPost", "BufWritePost" }, {
    group = group,
    callback = function(args)
      M.scan_buffer(args.buf)
    end,
  })

  if M.config.enable_realtime then
    vim.api.nvim_create_autocmd({ "TextChanged", "TextChangedI" }, {
      group = group,
      callback = function(args)
        schedule_scan(args.buf)
      end,
    })
  end

  vim.api.nvim_create_autocmd("BufDelete", {
    group = group,
    callback = function(args)
      local b = args.buf
      if debounce_timers[b] then
        debounce_timers[b]:stop()
        debounce_timers[b]:close()
        debounce_timers[b] = nil
      end
      M.buffer_stats[b] = nil
    end,
  })
end

return M
