//! PQCanary Core Engine
//! Memory-safe, high-performance cryptographic AST scanner.
//! This core is designed to be compiled to both native binaries and WebAssembly.

// Enforce strict memory safety paradigms
#![forbid(unsafe_code)]
#![allow(clippy::needless_bool, clippy::needless_range_loop)]

pub mod scanner;
pub mod refactor;
pub mod omega;
pub mod horizon;
pub mod bio;
pub mod wasm_bridge;
pub mod api;

#[cfg(test)]
pub mod tests;

use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

/// Represents an extracted cryptographic key or sensitive string.
/// Implements ZeroizeOnDrop to ensure memory is securely overwritten
/// when this struct goes out of scope, preventing memory-dump attacks.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecureMaterial {
    pub raw_bytes: Vec<u8>,
    pub file_path: String,
    pub line_number: u32,
}

impl SecureMaterial {
    pub fn new(bytes: Vec<u8>, path: &str, line: u32) -> Self {
        Self {
            raw_bytes: bytes,
            file_path: path.to_string(),
            line_number: line,
        }
    }
}
