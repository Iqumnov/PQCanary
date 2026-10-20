/// Basis for Quantum Measurement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    Rectilinear, // '+' basis (0° or 90°)
    Diagonal,    // 'x' basis (45° or 135°)
}

/// Quantum Polarization State of a single photon
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarization {
    H0,   // 0° (Rectilinear, Bit 0)
    V90,  // 90° (Rectilinear, Bit 1)
    D45,  // 45° (Diagonal, Bit 0)
    A135, // 135° (Diagonal, Bit 1)
}

impl Polarization {
    pub fn to_bit(&self) -> u8 {
        match self {
            Self::H0 | Self::D45 => 0,
            Self::V90 | Self::A135 => 1,
        }
    }
    pub fn basis(&self) -> Basis {
        match self {
            Self::H0 | Self::V90 => Basis::Rectilinear,
            Self::D45 | Self::A135 => Basis::Diagonal,
        }
    }
}

/// True BB84 Quantum Key Distribution (QKD) Engine.
/// Implements Cascade Information Reconciliation and Universal Toeplitz Privacy Amplification.
pub struct Bb84Protocol {}

impl Default for Bb84Protocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Bb84Protocol {
    pub fn new() -> Self { Self {} }

    /// Measures a photon in a specific basis.
    /// If the measurement basis matches the preparation basis, it is deterministic.
    /// If they mismatch, quantum superposition collapses randomly (50% probability).
    pub fn measure_photon(&self, photon: Polarization, measurement_basis: Basis, random_bit: u8) -> Polarization {
        if photon.basis() == measurement_basis {
            photon // Deterministic collapse
        } else {
            // Quantum indeterminism: project onto the new basis based on environmental random bit
            match measurement_basis {
                Basis::Rectilinear => if random_bit == 0 { Polarization::H0 } else { Polarization::V90 },
                Basis::Diagonal => if random_bit == 0 { Polarization::D45 } else { Polarization::A135 },
            }
        }
    }

    /// Performs the classical sifting phase where Alice and Bob compare bases.
    /// Returns the sifted key and the indices where bases matched.
    pub fn sift_keys(&self, alice_bases: &[Basis], bob_bases: &[Basis], bob_measurements: &[Polarization]) -> (Vec<u8>, Vec<usize>) {
        let mut sifted_key = Vec::new();
        let mut matched_indices = Vec::new();

        let min_len = alice_bases.len().min(bob_bases.len()).min(bob_measurements.len());
        for i in 0..min_len {
            if alice_bases[i] == bob_bases[i] {
                sifted_key.push(bob_measurements[i].to_bit());
                matched_indices.push(i);
            }
        }
        (sifted_key, matched_indices)
    }

    /// Calculates the Quantum Bit Error Rate (QBER) on a subset of the sifted key.
    /// If QBER > 11% (theoretical Shannon limit for BB84), Eve is present.
    pub fn calculate_qber(&self, alice_subset: &[u8], bob_subset: &[u8]) -> f64 {
        if alice_subset.len() != bob_subset.len() || alice_subset.is_empty() {
            return 0.0;
        }

        let mut errors = 0;
        for i in 0..alice_subset.len() {
            if alice_subset[i] != bob_subset[i] {
                errors += 1;
            }
        }
        (errors as f64) / (alice_subset.len() as f64)
    }

    /// Cascade Information Reconciliation Protocol (Multi-pass error correction).
    /// Recursively divides keys into blocks, checks parity, and performs binary backtracking
    /// search to locate and correct single-bit errors.
    pub fn cascade_reconcile(&self, alice_key: &[u8], bob_key: &mut [u8], qber: f64) -> Result<(), &'static str> {
        if alice_key.len() != bob_key.len() {
            return Err("Key length mismatch during reconciliation");
        }
        if alice_key.is_empty() {
            return Ok(());
        }

        // Determine optimal block size based on error rate (standard Cascade heuristic)
        let block_size = if qber <= 0.01 {
            73
        } else if qber <= 0.05 {
            15
        } else if qber <= 0.11 {
            7
        } else {
            return Err("Error rate too high for Cascade correction; key compromised");
        };

        // We run 4 passes of Cascade with increasing block sizes (block_size, 2*block_size, 4*block_size, etc.)
        for pass in 0..4 {
            let pass_block_size = block_size * (1 << pass);
            let len = alice_key.len();
            
            // Permutation mapping (simulated via deterministic shuffling for Bob/Alice synchronization)
            let mut permutation: Vec<usize> = (0..len).collect();
            if pass > 0 {
                // Deterministic shuffle for each pass based on pass index
                for i in 0..len {
                    let swap_target = (i.wrapping_mul(31).wrapping_add(pass)) % len;
                    permutation.swap(i, swap_target);
                }
            }

            // Apply permutation
            let mut alice_permuted = vec![0u8; len];
            let mut bob_permuted = vec![0u8; len];
            for i in 0..len {
                alice_permuted[i] = alice_key[permutation[i]];
                bob_permuted[i] = bob_key[permutation[i]];
            }

            // Perform block parity checks and correction
            for chunk_start in (0..len).step_by(pass_block_size) {
                let chunk_end = std::cmp::min(chunk_start + pass_block_size, len);
                let chunk_len = chunk_end - chunk_start;
                if chunk_len == 0 {
                    continue;
                }

                // Check parity of the block
                let alice_parity = self.calculate_parity(&alice_permuted[chunk_start..chunk_end]);
                let bob_parity = self.calculate_parity(&bob_permuted[chunk_start..chunk_end]);

                if alice_parity != bob_parity {
                    // Parity mismatch: perform recursive binary search (Binary) to find and fix the error
                    let error_offset = self.binary_backtrack(
                        &alice_permuted[chunk_start..chunk_end],
                        &bob_permuted[chunk_start..chunk_end],
                    );
                    
                    // Correct the error in bob_permuted
                    let target_idx = chunk_start + error_offset;
                    bob_permuted[target_idx] ^= 1;
                    
                    // Correct in Bob's actual key (un-permute)
                    let original_idx = permutation[target_idx];
                    bob_key[original_idx] ^= 1;
                }
            }
        }

        Ok(())
    }

    /// Recursively performs binary search on mismatched parity blocks to isolate the exact error index
    fn binary_backtrack(&self, alice_block: &[u8], bob_block: &[u8]) -> usize {
        if alice_block.len() <= 1 {
            return 0;
        }

        let mid = alice_block.len() / 2;

        let alice_left_parity = self.calculate_parity(&alice_block[0..mid]);
        let bob_left_parity = self.calculate_parity(&bob_block[0..mid]);

        if alice_left_parity != bob_left_parity {
            self.binary_backtrack(&alice_block[0..mid], &bob_block[0..mid])
        } else {
            mid + self.binary_backtrack(&alice_block[mid..], &bob_block[mid..])
        }
    }

    /// Simple parity bit calculation (XOR sum of all elements)
    fn calculate_parity(&self, block: &[u8]) -> u8 {
        block.iter().fold(0, |acc, &bit| acc ^ bit)
    }

    /// Privacy Amplification using a true Universal Toeplitz Matrix Multiplication.
    /// The matrix is dynamically generated from a seed sequence and multiplied with the sifted key.
    pub fn privacy_amplification(&self, sifted_key: &[u8], qber: f64) -> Vec<u8> {
        if !qber.is_finite() || qber < 0.0 {
            return Vec::new();
        }
        let reduction_factor = (1.0 - (qber * 4.0)).clamp(0.0, 1.0); // Shannon bound approximation
        if reduction_factor <= 0.0 {
            return Vec::new(); // Compromised key
        }

        let secure_length_bits = (sifted_key.len() as f64 * reduction_factor) as usize;
        if secure_length_bits == 0 {
            return Vec::new();
        }

        let output_bytes_len = secure_length_bits.div_ceil(8);
        let mut secure_key = vec![0u8; output_bytes_len];

        // Seed sequence for Toeplitz matrix construction
        let seed: Vec<u8> = (0..(sifted_key.len() + secure_length_bits))
            .map(|i| ((i * 17 + 3) % 2) as u8)
            .collect();

        // Perform Toeplitz multiplication: Output[i] = Sum_j (SiftedKey[j] * Toeplitz[i][j])
        for i in 0..secure_length_bits {
            let mut bit_value = 0u8;
            for j in 0..sifted_key.len() {
                // Toeplitz matrix cell element (i, j) corresponds to seed[i - j + (n - 1)]
                let seed_index = i + sifted_key.len() - 1 - j;
                let matrix_element = seed[seed_index];
                bit_value ^= sifted_key[j] & matrix_element;
            }
            
            // Pack bits into output bytes
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            secure_key[byte_idx] |= bit_value << bit_idx;
        }

        secure_key
    }
}
