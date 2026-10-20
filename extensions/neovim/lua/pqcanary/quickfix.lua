--[[
  PQCanary Quickfix Integration
  Populates Vim/Neovim Quickfix and Location Lists with Quantum Security Findings
  Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
--]]

local M = {}

local TYPE_MAP = {
  [vim.diagnostic.severity.ERROR] = "E",
  [vim.diagnostic.severity.WARN] = "W",
  [vim.diagnostic.severity.INFO] = "I",
  [vim.diagnostic.severity.HINT] = "I",
}

--- Populate the Quickfix list with findings
--- @param diagnostics table Array of diagnostics
--- @param title string Optional quickfix title
--- @param auto_open boolean Whether to run :copen automatically
function M.populate_quickfix(diagnostics, title, auto_open)
  local qf_list = {}
  local bufnr = vim.api.nvim_get_current_buf()
  local fname = vim.api.nvim_buf_get_name(bufnr)

  for _, d in ipairs(diagnostics) do
    local qtype = TYPE_MAP[d.severity] or "W"
    local first_line = vim.split(d.message, "\n")[1] or d.message

    table.insert(qf_list, {
      bufnr = d.bufnr or bufnr,
      filename = fname,
      lnum = (d.lnum or 0) + 1,
      col = (d.col or 0) + 1,
      text = string.format("[%s] %s", d.code or "PQCanary", first_line),
      type = qtype,
    })
  end

  local list_title = title or "PQCanary Quantum Audit Findings"
  vim.fn.setqflist(qf_list, "r")
  vim.fn.setqflist({}, "a", { title = list_title })

  if auto_open ~= false and #qf_list > 0 then
    vim.cmd("copen")
  end
end

--- Populate the Location list for the current window
--- @param diagnostics table Array of diagnostics
--- @param auto_open boolean Whether to open :lopen
function M.populate_loclist(diagnostics, auto_open)
  local qf_list = {}
  local bufnr = vim.api.nvim_get_current_buf()
  local fname = vim.api.nvim_buf_get_name(bufnr)

  for _, d in ipairs(diagnostics) do
    local qtype = TYPE_MAP[d.severity] or "W"
    local first_line = vim.split(d.message, "\n")[1] or d.message

    table.insert(qf_list, {
      bufnr = d.bufnr or bufnr,
      filename = fname,
      lnum = (d.lnum or 0) + 1,
      col = (d.col or 0) + 1,
      text = string.format("[%s] %s", d.code or "PQCanary", first_line),
      type = qtype,
    })
  end

  vim.fn.setloclist(0, qf_list, "r")
  vim.fn.setloclist(0, {}, "a", { title = "PQCanary (Current Buffer)" })

  if auto_open ~= false and #qf_list > 0 then
    vim.cmd("lopen")
  end
end

return M
