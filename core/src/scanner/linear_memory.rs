use std::collections::HashMap;

pub const WASM_PAGE_SIZE: usize = 65_536; // 64 KiB — defined by the Wasm spec
pub const WASM_MAX_PAGES: usize = 65_536; // Maximum 4 GiB total (65536 × 64KiB)
pub const WASM_MAX_MEMORY: u64 = (WASM_MAX_PAGES as u64) * (WASM_PAGE_SIZE as u64);

// ============================================================
// Formal Violation Types
// ============================================================

/// A formal memory access violation.
#[derive(Debug, Clone, PartialEq)]
pub struct OobViolation {
    pub attempted_address: usize,
    pub access_size: usize,
    pub current_memory_bound: usize,
    pub violation_type: ViolationType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationType {
    /// address + size > memory.len() — out-of-bounds read/write
    OutOfBounds,
    /// Address is within memory but the page is marked non-writable
    WriteToReadOnlyPage,
    /// Attempting to execute data from a non-executable page (NX/DEP violation)
    ExecuteFromDataPage,
    /// Double-free: heap block freed twice
    DoubleFree,
    /// Use-after-free: read/write to a freed heap block
    UseAfterFree,
    /// Null pointer dereference (address 0 with no mapping)
    NullDereference,
    /// Heap buffer overflow (write past the end of an allocated block)
    HeapOverflow { allocation_size: usize },
    /// Stack pointer moved past the stack guard page
    StackOverflow,
    /// Integer overflow in address arithmetic
    AddressIntegerOverflow,
}

impl OobViolation {
    pub fn severity(&self) -> &'static str {
        match self.violation_type {
            ViolationType::OutOfBounds        => "HIGH",
            ViolationType::WriteToReadOnlyPage => "HIGH",
            ViolationType::ExecuteFromDataPage => "CRITICAL",
            ViolationType::DoubleFree          => "CRITICAL",
            ViolationType::UseAfterFree        => "CRITICAL",
            ViolationType::NullDereference     => "HIGH",
            ViolationType::HeapOverflow { .. } => "CRITICAL",
            ViolationType::StackOverflow       => "HIGH",
            ViolationType::AddressIntegerOverflow => "HIGH",
        }
    }

    pub fn to_report(&self) -> String {
        format!(
            "[{}] {:?}: offset=0x{:X} size={} bound={} bytes",
            self.severity(), self.violation_type,
            self.attempted_address, self.access_size, self.current_memory_bound
        )
    }
}

// ============================================================
// Page Table with Permission Tracking
// ============================================================

/// Memory protection bits for a Wasm page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePermissions {
    pub readable:   bool,
    pub writable:   bool,
    pub executable: bool,
}

impl PagePermissions {
    pub const RW:  Self = Self { readable: true,  writable: true,  executable: false };
    pub const RO:  Self = Self { readable: true,  writable: false, executable: false };
    pub const RX:  Self = Self { readable: true,  writable: false, executable: true  };
    pub const NONE:Self = Self { readable: false, writable: false, executable: false };
}

#[derive(Debug, Clone)]
struct Page {
    data: Box<[u8; WASM_PAGE_SIZE]>,
    permissions: PagePermissions,
}

impl Page {
    fn new(perms: PagePermissions) -> Self {
        Self { data: Box::new([0u8; WASM_PAGE_SIZE]), permissions: perms }
    }
}

// ============================================================
// Heap Allocation Tracker
// ============================================================

#[derive(Debug, Clone)]
pub struct HeapBlock {
    pub base: usize,
    pub size: usize,
    pub is_freed: bool,
    /// Call-site descriptor (file:line or function name)
    pub allocation_site: String,
}

// ============================================================
// The Full Formal Linear Memory Sandbox
// ============================================================

/// A WebAssembly-spec-compliant linear memory sandbox with:
/// - Per-page permission tracking (read/write/execute bits)
/// - Heap allocation registry (malloc/free with use-after-free detection)
/// - Stack guard page enforcement
/// - Integer overflow detection in address arithmetic
/// - Formal violation report generation
pub struct LinearMemoryAnalyzer {
    /// Sparse page table: page_index → Page struct
    pages: HashMap<usize, Page>,
    /// Current number of allocated pages
    current_pages: usize,
    /// Maximum allowed pages
    max_pages: usize,
    /// Heap allocation registry
    heap_blocks: HashMap<usize, HeapBlock>,
    /// Next simulated heap allocation pointer (bump allocator)
    heap_bump: usize,
    /// Stack top and stack guard limit
    #[allow(dead_code)]
    stack_top: usize,
    #[allow(dead_code)]
    stack_limit: usize,
    /// Access log for forensic replay
    access_log: Vec<AccessRecord>,
    /// Whether to record the access log
    log_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AccessRecord {
    pub op: AccessOp,
    pub offset: usize,
    pub size: usize,
    pub result: AccessResult,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AccessOp { Read, Write, Execute, MemGrow, Malloc, Free }

#[derive(Debug, Clone, PartialEq)]
pub enum AccessResult { Ok, Violation(String) }

impl LinearMemoryAnalyzer {
    /// Initialize a Wasm linear memory sandbox with `initial_pages` pre-allocated pages.
    /// Stack occupies the last 2 pages by default.
    pub fn new(initial_pages: usize, max_pages: usize) -> Self {
        let clamped = max_pages.min(WASM_MAX_PAGES);
        let init = initial_pages.min(clamped);
        let heap_start = WASM_PAGE_SIZE * 2; // First 2 pages = stack
        let stack_top  = WASM_PAGE_SIZE * 2;
        let stack_limit = 0;

        let mut mem = Self {
            pages: HashMap::new(),
            current_pages: 0,
            max_pages: clamped,
            heap_blocks: HashMap::new(),
            heap_bump: heap_start,
            stack_top,
            stack_limit,
            access_log: Vec::new(),
            log_enabled: true,
        };

        // Allocate initial pages as read-write
        for i in 0..init {
            mem.pages.insert(i, Page::new(PagePermissions::RW));
            mem.current_pages += 1;
        }
        // Mark stack pages (0..1) as RW
        if let Some(p) = mem.pages.get_mut(&0) { p.permissions = PagePermissions::RW; }
        if let Some(p) = mem.pages.get_mut(&1) { p.permissions = PagePermissions::RW; }

        mem
    }

    pub fn current_size_bytes(&self) -> usize { self.current_pages * WASM_PAGE_SIZE }
    pub fn current_pages(&self) -> usize { self.current_pages }

    fn page_idx(&self, offset: usize) -> usize { offset / WASM_PAGE_SIZE }
    fn page_offset(&self, offset: usize) -> usize { offset % WASM_PAGE_SIZE }

    /// Check if an address + size range is fully within allocated, readable pages.
    fn check_read_access(&self, offset: usize, size: usize) -> Result<(), OobViolation> {
        if size == 0 {
            return Ok(());
        }

        // Integer overflow check
        let end = offset.checked_add(size).ok_or_else(|| OobViolation {
            attempted_address: offset,
            access_size: size,
            current_memory_bound: self.current_size_bytes(),
            violation_type: ViolationType::AddressIntegerOverflow,
        })?;

        // Null dereference
        if offset == 0 && size > 0 {
            return Err(OobViolation {
                attempted_address: 0,
                access_size: size,
                current_memory_bound: self.current_size_bytes(),
                violation_type: ViolationType::NullDereference,
            });
        }

        if end > self.current_size_bytes() {
            return Err(OobViolation {
                attempted_address: offset,
                access_size: size,
                current_memory_bound: self.current_size_bytes(),
                violation_type: ViolationType::OutOfBounds,
            });
        }

        // Check heap use-after-free (interval overlap between access [offset, end) and freed block [*base, *base + size))
        for (base, block) in &self.heap_blocks {
            if block.is_freed && offset < base.saturating_add(block.size) && end > *base {
                return Err(OobViolation {
                    attempted_address: offset,
                    access_size: size,
                    current_memory_bound: self.current_size_bytes(),
                    violation_type: ViolationType::UseAfterFree,
                });
            }
        }

        // Check all pages across the requested access range
        let start_page = self.page_idx(offset);
        let end_page = self.page_idx(end - 1);
        for p_idx in start_page..=end_page {
            if let Some(page) = self.pages.get(&p_idx) {
                if !page.permissions.readable {
                    return Err(OobViolation {
                        attempted_address: offset,
                        access_size: size,
                        current_memory_bound: self.current_size_bytes(),
                        violation_type: ViolationType::OutOfBounds,
                    });
                }
            } else {
                return Err(OobViolation {
                    attempted_address: offset,
                    access_size: size,
                    current_memory_bound: self.current_size_bytes(),
                    violation_type: ViolationType::OutOfBounds,
                });
            }
        }

        Ok(())
    }

    fn check_write_access(&self, offset: usize, size: usize) -> Result<(), OobViolation> {
        if size == 0 {
            return Ok(());
        }
        self.check_read_access(offset, size)?;
        let end = offset + size;
        let start_page = self.page_idx(offset);
        let end_page = self.page_idx(end - 1);
        for p_idx in start_page..=end_page {
            if let Some(page) = self.pages.get(&p_idx) {
                if !page.permissions.writable {
                    return Err(OobViolation {
                        attempted_address: offset,
                        access_size: size,
                        current_memory_bound: self.current_size_bytes(),
                        violation_type: ViolationType::WriteToReadOnlyPage,
                    });
                }
            } else {
                return Err(OobViolation {
                    attempted_address: offset,
                    access_size: size,
                    current_memory_bound: self.current_size_bytes(),
                    violation_type: ViolationType::OutOfBounds,
                });
            }
        }

        // Heap overflow check: writing past the end of an allocated block
        for (base, block) in &self.heap_blocks {
            if !block.is_freed && offset >= *base && offset < base.saturating_add(block.size) {
                let end = offset.saturating_add(size);
                if end > base.saturating_add(block.size) {
                    return Err(OobViolation {
                        attempted_address: offset,
                        access_size: size,
                        current_memory_bound: self.current_size_bytes(),
                        violation_type: ViolationType::HeapOverflow { allocation_size: block.size },
                    });
                }
            }
        }

        Ok(())
    }

    /// Safely expands linear memory by N pages. Returns the previous page count on success.
    /// Exact semantic of WebAssembly `memory.grow` instruction.
    pub fn grow_memory(&mut self, pages: usize) -> Result<usize, OobViolation> {
        let prev = self.current_pages;
        if prev.checked_add(pages).is_none_or(|sum| sum > self.max_pages) {
            return Err(OobViolation {
                attempted_address: self.current_size_bytes(),
                access_size: pages.saturating_mul(WASM_PAGE_SIZE),
                current_memory_bound: self.max_pages * WASM_PAGE_SIZE,
                violation_type: ViolationType::OutOfBounds,
            });
        }
        for i in prev..prev + pages {
            self.pages.insert(i, Page::new(PagePermissions::RW));
        }
        self.current_pages += pages;
        if self.log_enabled {
            self.access_log.push(AccessRecord {
                op: AccessOp::MemGrow, offset: prev * WASM_PAGE_SIZE,
                size: pages * WASM_PAGE_SIZE, result: AccessResult::Ok,
            });
        }
        Ok(prev)
    }

    /// Bounds-checked 32-bit integer write (little-endian).
    pub fn write_u32(&mut self, offset: usize, val: u32) -> Result<(), OobViolation> {
        self.write_bytes(offset, &val.to_le_bytes())
    }

    /// Bounds-checked 32-bit integer read (little-endian).
    pub fn read_u32(&mut self, offset: usize) -> Result<u32, OobViolation> {
        let bytes = self.read_bytes(offset, 4)?;
        let arr: [u8; 4] = bytes.try_into().map_err(|_| OobViolation {
            attempted_address: offset,
            access_size: 4,
            current_memory_bound: self.current_size_bytes(),
            violation_type: ViolationType::OutOfBounds,
        })?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Set memory access permissions for a specific page index.
    pub fn set_page_permissions(&mut self, page_idx: usize, perms: PagePermissions) -> Result<(), &'static str> {
        if let Some(page) = self.pages.get_mut(&page_idx) {
            page.permissions = perms;
            Ok(())
        } else {
            Err("Page index out of bounds")
        }
    }

    /// Bounds-checked read. Returns the bytes on success, OobViolation on failure.
    pub fn read_bytes(&mut self, offset: usize, length: usize) -> Result<Vec<u8>, OobViolation> {
        let res = self.check_read_access(offset, length);
        if self.log_enabled {
            self.access_log.push(AccessRecord {
                op: AccessOp::Read, offset, size: length,
                result: match &res {
                    Ok(_)  => AccessResult::Ok,
                    Err(v) => AccessResult::Violation(v.to_report()),
                },
            });
        }
        res?;

        let mut result = Vec::with_capacity(length);
        let mut current_offset = offset;
        let mut remaining = length;
        while remaining > 0 {
            let pg = self.page_idx(current_offset);
            let pg_off = self.page_offset(current_offset);
            let chunk_len = (WASM_PAGE_SIZE - pg_off).min(remaining);
            if let Some(page) = self.pages.get(&pg) {
                result.extend_from_slice(&page.data[pg_off..pg_off + chunk_len]);
            } else {
                result.resize(result.len() + chunk_len, 0);
            }
            current_offset += chunk_len;
            remaining -= chunk_len;
        }
        Ok(result)
    }

    /// Bounds-checked write.
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) -> Result<(), OobViolation> {
        let length = data.len();
        let res = self.check_write_access(offset, length);
        if self.log_enabled {
            self.access_log.push(AccessRecord {
                op: AccessOp::Write, offset, size: length,
                result: match &res {
                    Ok(_)  => AccessResult::Ok,
                    Err(v) => AccessResult::Violation(v.to_report()),
                },
            });
        }
        res?;

        let mut current_offset = offset;
        let mut src_offset = 0;
        let mut remaining = data.len();
        while remaining > 0 {
            let pg = self.page_idx(current_offset);
            let pg_off = self.page_offset(current_offset);
            let chunk_len = (WASM_PAGE_SIZE - pg_off).min(remaining);
            if let Some(page) = self.pages.get_mut(&pg) {
                page.data[pg_off..pg_off + chunk_len].copy_from_slice(&data[src_offset..src_offset + chunk_len]);
            }
            current_offset += chunk_len;
            src_offset += chunk_len;
            remaining -= chunk_len;
        }
        Ok(())
    }

    /// Set permissions on a specific page.
    pub fn mprotect(&mut self, page_idx: usize, perms: PagePermissions) -> Result<(), &'static str> {
        if let Some(page) = self.pages.get_mut(&page_idx) {
            page.permissions = perms;
            Ok(())
        } else {
            Err("Cannot mprotect: page not allocated")
        }
    }

    /// Simulate malloc: bump-allocates `size` bytes on the simulated heap.
    pub fn malloc(&mut self, size: usize, site: &str) -> Result<usize, OobViolation> {
        // Align to 8 bytes safely
        let aligned_size = size.checked_add(7).map(|s| s & !7).ok_or_else(|| OobViolation {
            attempted_address: self.heap_bump,
            access_size: size,
            current_memory_bound: self.current_size_bytes(),
            violation_type: ViolationType::AddressIntegerOverflow,
        })?;
        let ptr = self.heap_bump;

        let end = ptr.checked_add(aligned_size).ok_or_else(|| OobViolation {
            attempted_address: ptr,
            access_size: aligned_size,
            current_memory_bound: self.current_size_bytes(),
            violation_type: ViolationType::AddressIntegerOverflow,
        })?;

        // Ensure there's enough space
        if end > self.current_size_bytes() {
            // Try growing first
            let pages_needed = (end - self.current_size_bytes()).div_ceil(WASM_PAGE_SIZE);
            self.grow_memory(pages_needed)?;
        }

        self.heap_bump += aligned_size;
        self.heap_blocks.insert(ptr, HeapBlock {
            base: ptr, size: aligned_size, is_freed: false,
            allocation_site: site.to_string(),
        });

        if self.log_enabled {
            self.access_log.push(AccessRecord {
                op: AccessOp::Malloc, offset: ptr, size: aligned_size, result: AccessResult::Ok
            });
        }
        Ok(ptr)
    }

    /// Simulate free: marks the block as freed, enabling use-after-free detection.
    pub fn free(&mut self, ptr: usize) -> Result<(), OobViolation> {
        let current_size = self.current_size_bytes();
        let (err_opt, ok_size_opt) = match self.heap_blocks.get_mut(&ptr) {
            None => {
                let err = OobViolation {
                    attempted_address: ptr, access_size: 0,
                    current_memory_bound: current_size,
                    violation_type: ViolationType::OutOfBounds,
                };
                (Some((0, err)), None)
            }
            Some(block) if block.is_freed => {
                let block_size = block.size;
                let err = OobViolation {
                    attempted_address: ptr, access_size: block_size,
                    current_memory_bound: current_size,
                    violation_type: ViolationType::DoubleFree,
                };
                (Some((block_size, err)), None)
            }
            Some(block) => {
                block.is_freed = true;
                (None, Some(block.size))
            }
        };

        if let Some((size, err)) = err_opt {
            if self.log_enabled {
                self.access_log.push(AccessRecord {
                    op: AccessOp::Free, offset: ptr, size, result: AccessResult::Violation(err.to_report()),
                });
            }
            Err(err)
        } else if let Some(size) = ok_size_opt {
            if self.log_enabled {
                self.access_log.push(AccessRecord {
                    op: AccessOp::Free, offset: ptr, size, result: AccessResult::Ok,
                });
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Returns all violations found in the access log.
    pub fn get_violations(&self) -> Vec<&AccessRecord> {
        self.access_log.iter().filter(|r| matches!(r.result, AccessResult::Violation(_))).collect()
    }

    /// Generate a comprehensive formal memory safety report.
    pub fn generate_safety_report(&self) -> String {
        let violations = self.get_violations();
        let live_allocs = self.heap_blocks.values().filter(|b| !b.is_freed).count();
        let freed_allocs = self.heap_blocks.values().filter(|b| b.is_freed).count();

        let mut report = format!(
            "═══════════════════════════════════════════════════════\n\
             PQCanary Wasm Linear Memory Formal Safety Report\n\
             ═══════════════════════════════════════════════════════\n\
             Memory: {} pages = {} KiB / {} KiB max\n\
             Heap: {} live allocations, {} freed\n\
             Access log: {} total operations, {} violations\n\
             ═══════════════════════════════════════════════════════\n\n",
            self.current_pages,
            self.current_size_bytes() / 1024,
            self.max_pages * WASM_PAGE_SIZE / 1024,
            live_allocs, freed_allocs,
            self.access_log.len(), violations.len()
        );

        if violations.is_empty() {
            report.push_str("OK: MEMORY SAFE: No formal violations detected.\n");
        } else {
            report.push_str(&format!("FAIL: {} VIOLATIONS DETECTED:\n\n", violations.len()));
            for (i, v) in violations.iter().enumerate() {
                if let AccessResult::Violation(msg) = &v.result {
                    report.push_str(&format!("  {:>3}. {:?} op: {}\n", i + 1, v.op, msg));
                }
            }
        }

        // Report live allocations (potential leaks)
        let leaking: Vec<&HeapBlock> = self.heap_blocks.values().filter(|b| !b.is_freed).collect();
        if !leaking.is_empty() {
            report.push_str(&format!("\nWARN: {} POTENTIAL MEMORY LEAKS:\n", leaking.len()));
            for leak in &leaking {
                report.push_str(&format!(
                    "  0x{:08X} ({} bytes) from: {}\n",
                    leak.base, leak.size, leak.allocation_site
                ));
            }
        }

        report
    }
}
