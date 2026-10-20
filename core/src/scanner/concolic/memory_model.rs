use std::collections::HashMap;

/// System memory page size: 4 KiB
pub const PAGE_SIZE: u64 = 4096;

/// Standard virtual addresses for process segments
pub const TEXT_BASE: u64 = 0x0040_0000;
pub const DATA_BASE: u64 = 0x0060_0000;
pub const HEAP_BASE: u64 = 0x0100_0000;
pub const STACK_BASE: u64 = 0x7FFF_FFFF_0000;

/// Memory access permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Represents the state of a virtual memory page.
#[derive(Debug, Clone)]
pub struct MemoryPage {
    pub bytes: [MemoryByte; PAGE_SIZE as usize],
    pub permissions: PagePermissions,
}

/// Concrete byte or a symbolic SMT expression representing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryByte {
    Concrete(u8),
    Symbolic(String), // e.g. "sym_input_3"
}

impl Default for MemoryByte {
    fn default() -> Self {
        MemoryByte::Concrete(0)
    }
}

/// Represents a virtual File Descriptor for operating system simulations.
#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub fd: u32,
    pub path: String,
    pub content: Vec<MemoryByte>,
    pub offset: usize,
    pub permissions: PagePermissions,
}

/// Simulated memory allocation tracking
#[derive(Debug, Clone)]
pub struct Allocation {
    pub address: u64,
    pub size: usize,
    pub active: bool,
}

/// OS-level memory model mapping virtual addresses to symbolic/concrete byte pages,
/// simulating process segments, heap limits, page tables, VFS streams, and system calls.
#[derive(Debug, Clone)]
pub struct SymbolicMemoryModel {
    // Page table: Page base address -> Page content
    page_table: HashMap<u64, MemoryPage>,
    // Allocation registry (Heap allocations tracking for memory safety validation)
    pub allocations: HashMap<u64, Allocation>,
    // Simulated VFS file descriptor table
    fd_table: HashMap<u32, FileDescriptor>,
    next_fd: u32,

    // Segment pointer limits
    pub program_break: u64, // End of the heap (brk pointer)
    pub stack_pointer: u64, // Active stack base address
}

impl Default for SymbolicMemoryModel {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolicMemoryModel {
    pub fn new() -> Self {
        let mut model = Self {
            page_table: HashMap::new(),
            allocations: HashMap::new(),
            fd_table: HashMap::new(),
            next_fd: 3, // 0 = stdin, 1 = stdout, 2 = stderr
            program_break: HEAP_BASE,
            stack_pointer: STACK_BASE,
        };
        
        // Setup standard POSIX streams
        model.setup_std_fds();
        model
    }

    /// Initializes standard input, output, and error virtual streams
    fn setup_std_fds(&mut self) {
        let read_perm = PagePermissions { read: true, write: false, execute: false };
        let write_perm = PagePermissions { read: false, write: true, execute: false };

        self.fd_table.insert(0, FileDescriptor {
            fd: 0,
            path: "/dev/stdin".to_string(),
            content: Vec::new(),
            offset: 0,
            permissions: read_perm,
        });
        self.fd_table.insert(1, FileDescriptor {
            fd: 1,
            path: "/dev/stdout".to_string(),
            content: Vec::new(),
            offset: 0,
            permissions: write_perm,
        });
        self.fd_table.insert(2, FileDescriptor {
            fd: 2,
            path: "/dev/stderr".to_string(),
            content: Vec::new(),
            offset: 0,
            permissions: write_perm,
        });
    }

    /// Resolves virtual page index base address
    fn get_page_base(&self, address: u64) -> u64 {
        address & !(PAGE_SIZE - 1)
    }

    /// Checks if access to address matches target page permissions
    fn verify_memory_access(&self, address: u64, write: bool, execute: bool) -> Result<(), &'static str> {
        let base = self.get_page_base(address);
        if let Some(page) = self.page_table.get(&base) {
            if write && !page.permissions.write {
                return Err("Segmentation Fault: Write Access Violation");
            }
            if execute && !page.permissions.execute {
                return Err("Segmentation Fault: Data Execution Prevention (DEP) Active");
            }
            if !write && !execute && !page.permissions.read {
                return Err("Segmentation Fault: Read Access Violation");
            }
            Ok(())
        } else {
            Err("Segmentation Fault: Accessing Unmapped Virtual Address (Null Pointer or Wild dereference)")
        }
    }

    /// Maps a virtual memory region to the process page table
    pub fn sys_mmap(&mut self, address: u64, length: usize, permissions: PagePermissions) -> Result<u64, &'static str> {
        if length == 0 {
            return Err("Invalid argument: mmap length cannot be zero (EINVAL)");
        }
        if length > 64 * 1024 * 1024 {
            return Err("Requested mmap length exceeds maximum simulated memory limit (64 MiB)");
        }

        let base_addr = if address == 0 {
            // Find continuous free page block on heap
            self.program_break
        } else {
            self.get_page_base(address)
        };

        let num_pages = length.div_ceil(PAGE_SIZE as usize);

        for i in 0..num_pages {
            let page_addr = match base_addr.checked_add(i as u64 * PAGE_SIZE) {
                Some(addr) => addr,
                None => return Err("Segmentation Fault: Virtual address overflow"),
            };
            if self.page_table.contains_key(&page_addr) {
                return Err("Failed to map memory: Page conflicts");
            }
        }

        // Write pages into simulated kernel mappings
        for i in 0..num_pages {
            let page_addr = base_addr + (i as u64 * PAGE_SIZE);
            self.page_table.insert(page_addr, MemoryPage {
                bytes: std::array::from_fn(|_| MemoryByte::Concrete(0)),
                permissions,
            });
        }

        if address == 0 {
            self.program_break = self.program_break
                .checked_add(num_pages as u64 * PAGE_SIZE)
                .ok_or("Heap limit exceeded: address space overflow")?;
        }

        Ok(base_addr)
    }

    /// POSIX `sys_brk`: Modifies the process heap space boundary
    pub fn sys_brk(&mut self, new_break: u64) -> Result<u64, &'static str> {
        if new_break < HEAP_BASE {
            return Err("Invalid process break boundary");
        }

        if new_break > self.program_break {
            let diff = (new_break - self.program_break) as usize;
            self.sys_mmap(self.program_break, diff, PagePermissions { read: true, write: true, execute: false })?;
        } else if new_break < self.program_break {
            // brk decrease: unmap pages
            let mut current = self.get_page_base(self.program_break);
            let target_base = self.get_page_base(new_break);
            while current > target_base {
                current -= PAGE_SIZE;
                self.page_table.remove(&current);
            }
            self.program_break = new_break;
        }
        Ok(self.program_break)
    }

    /// Simulated malloc: Allocates size bytes with boundaries tracking
    pub fn malloc(&mut self, size: usize) -> Result<u64, &'static str> {
        let alloc_size = if size == 0 { 1 } else { size };
        let ptr = self.sys_mmap(0, alloc_size, PagePermissions { read: true, write: true, execute: false })?;
        self.allocations.insert(ptr, Allocation {
            address: ptr,
            size: alloc_size,
            active: true,
        });
        Ok(ptr)
    }

    /// Simulated free: Revokes allocated address mapping and sets active flag to false
    pub fn free(&mut self, address: u64) -> Result<(), &'static str> {
        if let Some(alloc) = self.allocations.get_mut(&address) {
            if !alloc.active {
                return Err("Double Free detected: Memory chunk already deallocated");
            }
            alloc.active = false;
            // POSIX requires returning pages, we unmap the base allocation range
            let num_pages = alloc.size.div_ceil(PAGE_SIZE as usize);
            for i in 0..num_pages {
                let page_addr = address + (i as u64 * PAGE_SIZE);
                self.page_table.remove(&page_addr);
            }
            Ok(())
        } else {
            Err("Invalid free: Address is not a valid allocated heap block")
        }
    }

    /// Read byte from simulated address space
    pub fn read_byte(&self, address: u64) -> Result<MemoryByte, &'static str> {
        self.verify_memory_access(address, false, false)?;
        let base = self.get_page_base(address);
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        
        let page = self.page_table.get(&base).ok_or("Null reference error")?;
        Ok(page.bytes[offset].clone())
    }

    /// Write byte into simulated address space
    pub fn write_byte(&mut self, address: u64, value: MemoryByte) -> Result<(), &'static str> {
        self.verify_memory_access(address, true, false)?;
        let base = self.get_page_base(address);
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        
        let page = self.page_table.get_mut(&base).ok_or("Null reference error")?;
        page.bytes[offset] = value;
        Ok(())
    }

    /// Allocates symbolic buffer variables directly onto the stack or heap for concolic analysis
    pub fn allocate_symbolic_buffer(&mut self, size: usize, prefix: &str) -> Result<u64, &'static str> {
        let ptr = self.malloc(size)?;
        for i in 0..size {
            let sym_name = format!("{}_{}", prefix, i);
            let byte_addr = match ptr.checked_add(i as u64) {
                Some(addr) => addr,
                None => return Err("Address overflow in symbolic buffer"),
            };
            self.write_byte(byte_addr, MemoryByte::Symbolic(sym_name))?;
        }
        Ok(ptr)
    }

    /// POSIX file systems sys_open: maps a path to the file descriptor table
    pub fn sys_open(&mut self, path: &str, content: Vec<u8>) -> u32 {
        let fd = self.next_fd;
        self.next_fd += 1;

        let memory_content = content.into_iter().map(MemoryByte::Concrete).collect();

        self.fd_table.insert(fd, FileDescriptor {
            fd,
            path: path.to_string(),
            content: memory_content,
            offset: 0,
            permissions: PagePermissions { read: true, write: true, execute: false },
        });
        fd
    }

    /// POSIX sys_read: reads from file descriptor and writes into simulated buffer pointer
    pub fn sys_read(&mut self, fd: u32, buf_ptr: u64, count: usize) -> Result<usize, &'static str> {
        let mut file = self.fd_table.remove(&fd).ok_or("Bad File Descriptor (EBADF)")?;
        if !file.permissions.read {
            self.fd_table.insert(fd, file);
            return Err("Permission Denied: File not open for read operations");
        }

        let mut read_bytes = 0;
        for i in 0..count {
            if file.offset >= file.content.len() {
                break;
            }
            let target_addr = match buf_ptr.checked_add(i as u64) {
                Some(addr) => addr,
                None => {
                    self.fd_table.insert(fd, file);
                    return Err("Buffer address overflow during sys_read");
                }
            };
            let byte = file.content[file.offset].clone();
            if let Err(e) = self.write_byte(target_addr, byte) {
                self.fd_table.insert(fd, file);
                return Err(e);
            }
            file.offset += 1;
            read_bytes += 1;
        }

        self.fd_table.insert(fd, file);
        Ok(read_bytes)
    }

    /// POSIX sys_write: reads from simulated buffer pointer and writes to file descriptor
    pub fn sys_write(&mut self, fd: u32, buf_ptr: u64, count: usize) -> Result<usize, &'static str> {
        let mut file = self.fd_table.remove(&fd).ok_or("Bad File Descriptor (EBADF)")?;
        if !file.permissions.write {
            self.fd_table.insert(fd, file);
            return Err("Permission Denied: File not open for write operations");
        }

        for i in 0..count {
            let target_addr = match buf_ptr.checked_add(i as u64) {
                Some(addr) => addr,
                None => {
                    self.fd_table.insert(fd, file);
                    return Err("Buffer address overflow during sys_write");
                }
            };
            match self.read_byte(target_addr) {
                Ok(byte) => file.content.push(byte),
                Err(e) => {
                    self.fd_table.insert(fd, file);
                    return Err(e);
                }
            }
        }

        self.fd_table.insert(fd, file);
        Ok(count)
    }
}
