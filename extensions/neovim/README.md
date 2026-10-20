# PQCanary — Neovim & Vim Plugin

> **Real-time Post-Quantum Cryptographic Security Scanner & Linter for Neovim and Classic Vim**  
> *Author: Matvei Igumnov | License: Apache License 2.0*

PQCanary detects quantum-vulnerable cryptographic algorithms (RSA, ECC, Diffie-Hellman, DSA, broken hashes) directly in your editor as you type and provides one-click automated remediation to NIST FIPS Post-Quantum Standards (ML-KEM, ML-DSA, SLH-DSA).

---

## Features

- **Real-Time Diagnostics**: As-you-type background scanning debounced at 200ms using native `vim.diagnostic`.
- **193+ Cryptographic Signatures**: Detects classic public-key algorithms, symmetric deprecations, weak key sizes, and validates NIST FIPS 203/204/205 PQC implementations.
- **Instant Remediation (`:PQCanaryFix`)**: Automated code fix replacing quantum-vulnerable primitives with NIST-standardized PQC replacements (e.g. `RSA-2048` → `ML-KEM-768`, `ECDSA` → `ML-DSA-65`).
- **Quickfix & Location List Integration**: Jump across all quantum issues in your workspace with `:PQCanaryQuickfix` (`:copen` / `:lopen`).
- **Security Health Grade (`:PQCanaryStatus`)**: Instant calculation of file quantum security posture (A+ through F).
- **Zero External Dependencies**: Runs out of the box with pure Lua and Neovim's built-in C regex engine; seamlessly interfaces with the `pqcanary` CLI binary if installed.
- **Classic Vim Compatible**: Backward-compatible Vimscript fallback with `:setqflist` integration.

---

## Installation

### [lazy.nvim](https://github.com/folke/lazy.nvim)
```lua
{
  "Iqumnov/PQCanary",
  config = function()
    require("pqcanary").setup({
      enable_realtime = true,
      debounce_ms = 200,
      virtual_text = true,
      signs = true,
    })
  end,
}
```

### [packer.nvim](https://github.com/wbthomason/packer.nvim)
```lua
use {
  "Iqumnov/PQCanary",
  config = function()
    require("pqcanary").setup()
  end
}
```

### [vim-plug](https://github.com/junegunn/vim-plug) (Vim & Neovim)
```vim
Plug 'Iqumnov/PQCanary'
```

---

## Configuration

```lua
require("pqcanary").setup({
  enable_realtime = true,   -- Scan automatically on TextChanged and BufWritePost
  debounce_ms = 200,        -- Delay in milliseconds before scanning on keypress
  virtual_text = true,      -- Show inline diagnostic text
  signs = true,             -- Show gutter signs (Critical, High, Medium, Safe)
  underline = true,         -- Underline vulnerable tokens in code
  min_severity = "INFO",    -- Filter threshold: CRITICAL, HIGH, MEDIUM, LOW, INFO
  auto_quickfix = false,    -- Automatically open quickfix list on detection
  prefer_cli = false,       -- Use external `pqcanary` CLI executable if found
})
```

---

## Commands & Keymaps

| Command | Description |
|---|---|
| `:PQCanaryScan` | Manually run a full scan on the current buffer |
| `:PQCanaryFix` | Automatically replace the quantum-vulnerable primitive under the cursor with its NIST PQC equivalent |
| `:PQCanaryQuickfix` | Open the Quickfix list (`:copen`) populated with all quantum findings |
| `:PQCanaryStatus` | Display quantum security health score and vulnerability breakdown |
| `:PQCanaryToggle` | Toggle real-time linting on and off |

### Recommended Keymaps
```lua
vim.keymap.set("n", "<leader>qs", "<cmd>PQCanaryScan<cr>", { desc = "PQCanary: Scan Buffer" })
vim.keymap.set("n", "<leader>qf", "<cmd>PQCanaryFix<cr>", { desc = "PQCanary: Apply PQC Fix" })
vim.keymap.set("n", "<leader>qq", "<cmd>PQCanaryQuickfix<cr>", { desc = "PQCanary: Open Quickfix" })
vim.keymap.set("n", "<leader>qi", "<cmd>PQCanaryStatus<cr>", { desc = "PQCanary: Security Status" })
vim.keymap.set("n", "<leader>qt", "<cmd>PQCanaryToggle<cr>", { desc = "PQCanary: Toggle Real-time" })
```

---

## Statusline Integration (Lualine)

```lua
require("lualine").setup({
  sections = {
    lualine_x = {
      {
        function()
          return require("pqcanary").get_status()
        end,
        cond = function()
          return package.loaded["pqcanary"] ~= nil
        end,
      },
    },
  },
})
```

---

## License & Authorship

**Copyright (C) 2026 Matvei Igumnov**  
Licensed under the **Apache License, Version 2.0 (Apache-2.0)**.  
Under Apache 2.0 terms, anyone creating forks or derivative distributions may freely integrate, modify, and distribute the work commercially, provided proper copyright notice and attribution to **Matvei Igumnov** are retained.
