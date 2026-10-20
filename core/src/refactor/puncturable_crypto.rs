use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};

// ============================================================
// Puncturable Pseudorandom Function (PPRF) via GGM Tree
// ============================================================
//
// A puncturable PRF allows a party to derive a "punctured" key that can evaluate
// the PRF on all inputs EXCEPT for a specific set of revoked (punctured) inputs.
// We implement this using the Goldreich-Goldwasser-Micali (GGM) tree construction.
//
// Root is the master key. Left child = Hash(parent || 0), Right = Hash(parent || 1).
// Leaves of the tree (depth D) correspond to the PRF outputs for an integer input x.
// Puncturing at input `x` means deleting the path from root to leaf `x` and issuing
// all the sibling nodes along that path.

const HASH_LEN: usize = 32;

/// A 256-bit symmetric key or node in the GGM tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TreeNode(pub [u8; HASH_LEN]);

/// A punctured key that can evaluate the PRF everywhere except at punctured indices.
#[derive(Debug, Clone)]
pub struct PuncturedKey {
    pub tree_depth: usize,
    /// The set of nodes that form the "co-path" forest allowing evaluation
    /// without knowing the master root.
    /// Keyed by their level and path prefix.
    pub copath_nodes: HashMap<(usize, u64), TreeNode>,
    /// The indices that have been explicitly punctured
    pub punctured_indices: HashSet<u64>,
}

/// The full puncturable encryption engine holding the master key.
pub struct PuncturableEncryption {
    master_root: TreeNode,
    tree_depth: usize,
}

impl PuncturableEncryption {
    /// Initialize with a random 256-bit master key and a tree depth.
    /// A tree depth of 32 allows 2^32 possible inputs (ciphertexts/messages).
    pub fn new(master_key: [u8; HASH_LEN], tree_depth: usize) -> Self {
        assert!(tree_depth > 0 && tree_depth <= 64);
        Self {
            master_root: TreeNode(master_key),
            tree_depth,
        }
    }

    /// PRG: Expand a parent node into left (0) and right (1) children using SHA-256.
    fn expand_node(parent: &TreeNode) -> (TreeNode, TreeNode) {
        let mut hasher_left = Sha256::new();
        hasher_left.update(parent.0);
        hasher_left.update([0u8]); // Left child domain separation
        let left = hasher_left.finalize();

        let mut hasher_right = Sha256::new();
        hasher_right.update(parent.0);
        hasher_right.update([1u8]); // Right child domain separation
        let right = hasher_right.finalize();

        let mut l_arr = [0u8; 32];
        let mut r_arr = [0u8; 32];
        l_arr.copy_from_slice(&left);
        r_arr.copy_from_slice(&right);

        (TreeNode(l_arr), TreeNode(r_arr))
    }

    /// Evaluate the PRF at a specific index using the master key.
    /// This derives the leaf node for the given input.
    pub fn eval_master(&self, index: u64) -> TreeNode {
        let index = if self.tree_depth >= 64 { index } else { index & ((1u64 << self.tree_depth) - 1) };
        let mut current = self.master_root.clone();
        for level in (0..self.tree_depth).rev() {
            let bit = (index >> level) & 1;
            let (left, right) = Self::expand_node(&current);
            current = if bit == 0 { left } else { right };
        }
        current
    }

    /// Generate a punctured key that revokes the ability to decrypt the given index.
    /// Emits the co-path nodes required to reconstruct all other leaves.
    pub fn puncture_key(&self, index_to_revoke: u64) -> PuncturedKey {
        let index_to_revoke = if self.tree_depth >= 64 { index_to_revoke } else { index_to_revoke & ((1u64 << self.tree_depth) - 1) };
        let mut copath = HashMap::new();
        let mut current = self.master_root.clone();

        for level in (0..self.tree_depth).rev() {
            let bit = (index_to_revoke >> level) & 1;
            let (left, right) = Self::expand_node(&current);

            let depth = self.tree_depth - level; // 1 to tree_depth
            let prefix = index_to_revoke >> level; // Path prefix up to this level

            if bit == 0 {
                // We go left, so we add the right sibling to the copath
                let sibling_prefix = prefix ^ 1; // Flip the last bit to get sibling
                copath.insert((depth, sibling_prefix), right);
                current = left;
            } else {
                // We go right, so we add the left sibling to the copath
                let sibling_prefix = prefix ^ 1;
                copath.insert((depth, sibling_prefix), left);
                current = right;
            }
        }

        let mut punctured = HashSet::new();
        punctured.insert(index_to_revoke);

        PuncturedKey {
            tree_depth: self.tree_depth,
            copath_nodes: copath,
            punctured_indices: punctured,
        }
    }
}

impl PuncturedKey {
    /// PRG expansion logic (same as master).
    fn expand_node(parent: &TreeNode) -> (TreeNode, TreeNode) {
        let mut hasher_left = Sha256::new();
        hasher_left.update(parent.0);
        hasher_left.update([0u8]);
        let left = hasher_left.finalize();

        let mut hasher_right = Sha256::new();
        hasher_right.update(parent.0);
        hasher_right.update([1u8]);
        let right = hasher_right.finalize();

        let mut l_arr = [0u8; 32];
        let mut r_arr = [0u8; 32];
        l_arr.copy_from_slice(&left);
        r_arr.copy_from_slice(&right);

        (TreeNode(l_arr), TreeNode(r_arr))
    }

    /// Evaluate the PRF using a punctured key.
    /// Returns None if the index has been punctured (forward secrecy achieved).
    pub fn eval(&self, index: u64) -> Option<TreeNode> {
        let index = if self.tree_depth >= 64 { index } else { index & ((1u64 << self.tree_depth) - 1) };
        if self.punctured_indices.contains(&index) {
            return None; // Mathematically impossible to evaluate
        }

        // Find the deepest matching co-path node that covers this index
        for level in (0..self.tree_depth).rev() {
            let depth = self.tree_depth - level;
            let prefix = index >> level;

            if let Some(node) = self.copath_nodes.get(&(depth, prefix)) {
                // We found a covering node. Now derive the rest of the path down to the leaf.
                let mut current = node.clone();
                for sub_level in (0..level).rev() {
                    let bit = (index >> sub_level) & 1;
                    let (left, right) = Self::expand_node(&current);
                    current = if bit == 0 { left } else { right };
                }
                return Some(current);
            }
        }

        // If we reach here and haven't found a covering node, the key state is invalid
        None
    }

    /// Combine this punctured key with another puncturing operation.
    /// Allows iterative forward secrecy (puncturing sequentially over time).
    pub fn puncture_further(&mut self, index_to_revoke: u64) -> Result<(), &'static str> {
        let index_to_revoke = if self.tree_depth >= 64 { index_to_revoke } else { index_to_revoke & ((1u64 << self.tree_depth) - 1) };
        if self.punctured_indices.contains(&index_to_revoke) {
            return Ok(()); // Already punctured
        }

        // We must evaluate down to the leaf, taking the co-path nodes of the revoked path,
        // just like the master, but starting from the highest available covering node.
        let mut covering_depth = 0;
        let mut covering_node = None;
        let mut prefix_at_cover = 0;

        for level in (0..self.tree_depth).rev() {
            let depth = self.tree_depth - level;
            let prefix = index_to_revoke >> level;
            if let Some(node) = self.copath_nodes.remove(&(depth, prefix)) {
                covering_depth = depth;
                covering_node = Some(node);
                prefix_at_cover = prefix;
                break;
            }
        }

        let mut current = covering_node.ok_or("Cannot puncture: covering node not found")?;
        let remaining_levels = self.tree_depth - covering_depth;

        // Validate GGM tree invariant: the covering node prefix must share the high bits
        // of the index being revoked (the covering subtree contains the target leaf).
        debug_assert_eq!(
            if remaining_levels >= 64 { 0 } else { index_to_revoke >> remaining_levels },
            prefix_at_cover,
            "GGM tree invariant violated: covering prefix does not match index high bits"
        );


        // Traverse down from the covering node, adding siblings to the copath
        for i in 0..remaining_levels {
            let sub_level = remaining_levels - 1 - i;
            let bit = (index_to_revoke >> sub_level) & 1;
            let (left, right) = Self::expand_node(&current);

            let depth = covering_depth + i + 1;
            let prefix = index_to_revoke >> sub_level;
            let sibling_prefix = prefix ^ 1;

            if bit == 0 {
                self.copath_nodes.insert((depth, sibling_prefix), right);
                current = left;
            } else {
                self.copath_nodes.insert((depth, sibling_prefix), left);
                current = right;
            }
        }

        self.punctured_indices.insert(index_to_revoke);
        Ok(())
    }
}
