" ============================================================================
" PQCanary Plugin Loader for Vim & Neovim
" Real-time Post-Quantum Cryptographic Security Audit
" Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
" ============================================================================

if exists('g:loaded_pqcanary')
  finish
endif
let g:loaded_pqcanary = 1

" Configuration defaults for Classic Vim
if !exists('g:pqcanary_auto_scan')
  let g:pqcanary_auto_scan = 1
endif

if !exists('g:pqcanary_open_quickfix')
  let g:pqcanary_open_quickfix = 1
endif

" ----------------------------------------------------------------------------
" Neovim Bridge
" ----------------------------------------------------------------------------
if has('nvim')
  lua << EOF
  -- Automatically setup PQCanary with default options if user hasn't explicitly called setup()
  if vim.g.pqcanary_auto_setup ~= 0 then
    require('pqcanary').setup()
  end
EOF
  finish
endif

" ----------------------------------------------------------------------------
" Classic Vim Implementation
" ----------------------------------------------------------------------------

" Built-in regex patterns for classic Vim fallback
let s:classic_patterns = [
  \ {'id': 'RSA-CLASSIC', 'pattern': '\c\<\(RSA[_\-]\?1024\|RSA[_\-]\?2048\|RSA[_\-]\?4096\|RSA_PKCS1_PADDING\)\>', 'risk': 'CRITICAL', 'msg': 'Classical RSA is broken by Shor Algorithm. Migrate to ML-KEM (FIPS 203) or ML-DSA (FIPS 204).'},
  \ {'id': 'ECC-CLASSIC', 'pattern': '\c\<\(secp256r1\|secp384r1\|prime256v1\|ECDSA\|ECDH\|X25519\|Ed25519\)\>', 'risk': 'CRITICAL', 'msg': 'Elliptic Curve Cryptography is vulnerable to quantum cryptanalysis. Migrate to ML-DSA or X25519MLKEM768.'},
  \ {'id': 'HASH-WEAK', 'pattern': '\c\<\(MD5\|SHA1\|SHA-1\|DES\|3DES\|RC4\)\>', 'risk': 'HIGH', 'msg': 'Broken cryptographic primitive. Migrate to SHA3-256 or AES-256-GCM.'},
  \ {'id': 'PQC-SAFE', 'pattern': '\c\<\(ML-KEM-768\|ML-DSA-65\|SLH-DSA\|Kyber\|Dilithium\|SPHINCS\+\)\>', 'risk': 'SAFE', 'msg': 'Post-Quantum Safe Primitive.'}
\ ]

function! s:PQCanaryClassicScan() abort
  let l:qf = []
  let l:bufnr = bufnr('%')
  let l:filename = expand('%:p')

  " Check if external CLI binary is available
  if executable('pqcanary')
    let l:cmd = 'pqcanary scan ' . shellescape(l:filename) . ' --format json'
    let l:raw = system(l:cmd)
    if v:shell_error == 0 && !empty(l:raw)
      try
        let l:data = json_decode(l:raw)
        if has_key(l:data, 'findings')
          for l:f in l:data.findings
            call add(l:qf, {
              \ 'bufnr': l:bufnr,
              \ 'filename': l:filename,
              \ 'lnum': get(l:f, 'line', 1),
              \ 'col': get(l:f, 'column', 1),
              \ 'text': '[' . get(l:f, 'rule_id', 'PQ') . '] ' . get(l:f, 'description', 'Quantum vulnerability') . ' -> Remediation: ' . get(l:f, 'remediation', 'Migrate to PQC'),
              \ 'type': get(l:f, 'severity', '') ==# 'CRITICAL' ? 'E' : 'W'
            \ })
          endfor
        endif
      catch
      endtry
    endif
  endif

  " Fallback to buffer regex search if CLI was not used or returned no findings
  if empty(l:qf)
    let l:total_lines = line('$')
    for l:lnum in range(1, l:total_lines)
      let l:line_content = getline(l:lnum)
      for l:pat in s:classic_patterns
        let l:pos = match(l:line_content, l:pat.pattern)
        if l:pos != -1
          call add(l:qf, {
            \ 'bufnr': l:bufnr,
            \ 'filename': l:filename,
            \ 'lnum': l:lnum,
            \ 'col': l:pos + 1,
            \ 'text': '[' . l:pat.id . '] ' . l:pat.msg,
            \ 'type': l:pat.risk ==# 'CRITICAL' ? 'E' : (l:pat.risk ==# 'HIGH' ? 'W' : 'I')
          \ })
        endif
      endfor
    endfor
  endif

  call setqflist(l:qf, 'r')
  call setqflist([], 'a', {'title': 'PQCanary Quantum Security Audit'})

  if !empty(l:qf)
    echomsg 'PQCanary: Found ' . len(l:qf) . ' quantum cryptographic issues.'
    if g:pqcanary_open_quickfix
      copen
    endif
  else
    echomsg 'PQCanary: No quantum vulnerabilities detected in current buffer.'
  endif
endfunction

function! s:PQCanaryClassicToggle() abort
  let g:pqcanary_auto_scan = !g:pqcanary_auto_scan
  if g:pqcanary_auto_scan
    echomsg 'PQCanary: Automatic scanning enabled.'
    call s:PQCanaryClassicScan()
  else
    echomsg 'PQCanary: Automatic scanning disabled.'
    call setqflist([], 'r')
  endif
endfunction

" User Commands
command! -nargs=0 PQCanaryScan call s:PQCanaryClassicScan()
command! -nargs=0 PQCanaryToggle call s:PQCanaryClassicToggle()
command! -nargs=0 PQCanaryQuickfix copen

" Auto-scan on file write
augroup PQCanaryVimAuto
  autocmd!
  autocmd BufWritePost * if g:pqcanary_auto_scan && empty(&buftype) | call s:PQCanaryClassicScan() | endif
augroup END
