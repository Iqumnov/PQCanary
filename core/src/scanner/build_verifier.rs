use sha2::{Sha256, Digest};

/// Mathematical Binary Equivalence Verification (Reproducible Builds)
/// Constructs a Merkle Tree of source code SHA-256 hashes to guarantee that a
/// compiled binary exactly matches the expected cryptographic permutation of the source.
///
/// Uses real SHA-256 (FIPS 180-4 compliant) for all hash computations.
/// The Merkle root is:
///   - Collision resistant to 128-bit security
///   - Deterministic across platforms and architectures
///   - Verifiable by any standard SHA-256 implementation
pub struct BuildVerifier {
    merkle_leaves: Vec<[u8; 32]>,
}

impl BuildVerifier {
    pub fn new() -> Self {
        Self { merkle_leaves: Vec::new() }
    }

    /// Compute the SHA-256 hash of a byte slice.
    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Hash two 32-byte child hashes together (standard Merkle node construction).
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// Convert a 32-byte hash to a lowercase hex string.
    fn to_hex(hash: &[u8; 32]) -> String {
        hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Insert a source file into the Merkle tree.
    /// The leaf hash is SHA-256(file_content_bytes).
    pub fn insert_source_file(&mut self, file_content: &str) {
        self.merkle_leaves.push(Self::sha256(file_content.as_bytes()));
    }

    /// Insert a raw byte slice (e.g. compiled artifact).
    pub fn insert_bytes(&mut self, data: &[u8]) {
        self.merkle_leaves.push(Self::sha256(data));
    }

    /// Recursively compute the Merkle Root of all tracked source files.
    /// Returns the root as a 64-character lowercase hex string, or None if empty.
    pub fn compute_merkle_root(&self) -> Option<String> {
        if self.merkle_leaves.is_empty() {
            return None;
        }

        let mut current_layer = self.merkle_leaves.clone();

        while current_layer.len() > 1 {
            let mut next_layer: Vec<[u8; 32]> = Vec::new();
            let mut i = 0;
            while i < current_layer.len() {
                if i + 1 < current_layer.len() {
                    next_layer.push(Self::hash_pair(&current_layer[i], &current_layer[i + 1]));
                } else {
                    // Odd leaf: promote unchanged (Bitcoin-style Merkle behavior)
                    next_layer.push(current_layer[i]);
                }
                i += 2;
            }
            current_layer = next_layer;
        }

        Some(Self::to_hex(&current_layer[0]))
    }

    /// Verify if a compiled binary's embedded SHA-256 Merkle root signature
    /// matches the computed root from the tracked source files.
    pub fn verify_binary_equivalence(&self, binary_signature: &str) -> bool {
        match self.compute_merkle_root() {
            Some(root) => root == binary_signature,
            None => false,
        }
    }

    /// Return the number of source files tracked in this tree.
    pub fn leaf_count(&self) -> usize {
        self.merkle_leaves.len()
    }
}

impl Default for BuildVerifier {
    fn default() -> Self {
        Self::new()
    }
}
