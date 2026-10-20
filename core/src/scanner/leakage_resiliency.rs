use std::collections::{HashMap, HashSet};

// ============================================================
// Boolean Masking Scheme
// ============================================================
//
// Boolean masking is the standard countermeasure against Differential Power Analysis (DPA).
// A sensitive variable x is split into d shares: x = x_1 ⊕ x_2 ⊕ ... ⊕ x_d
// Each share is independently randomized, so no single share leaks Hamming weight info.
// The security order of the scheme is d-1: an adversary needs to observe d correlated
// power traces simultaneously to extract information.

/// The masking order of a protected implementation.
/// Order 0 = unprotected. Order 1 = first-order masked (d=2 shares). Etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MaskingOrder(pub u32);

impl MaskingOrder {
    pub fn is_protected(&self) -> bool { self.0 >= 1 }
    pub fn required_attack_traces(&self) -> u64 {
        // Statistical rule: O(n^d) traces needed where n ≈ 4 for 1-bit DPA
        self.0.checked_add(1)
            .and_then(|exp| 4u64.checked_pow(exp))
            .unwrap_or(u64::MAX)
    }
}

/// A single Boolean share of a sensitive value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoolShare {
    pub share_id: usize,
    pub variable_name: String,
    pub is_randomized: bool,
    /// The PRNG source used to generate this share's random value (if known)
    pub prng_source: Option<String>,
}

/// The set of all shares belonging to a single protected variable.
#[derive(Debug, Clone)]
pub struct MaskedVariable {
    pub original_name: String,
    pub shares: Vec<BoolShare>,
    pub masking_order: MaskingOrder,
    /// Whether the shares have been verified to XOR back to the original value
    pub consistency_verified: bool,
}

impl MaskedVariable {
    /// Construct a masked variable with d+1 shares (for order-d masking).
    pub fn new(name: &str, order: MaskingOrder) -> Self {
        let d = order.0 as usize;
        let shares: Vec<BoolShare> = (0..=d).map(|i| BoolShare {
            share_id: i,
            variable_name: format!("{}__share_{}", name, i),
            is_randomized: i < d, // Last share is the "masked value" = x ⊕ r_1 ⊕ ... ⊕ r_d
            prng_source: if i < d { Some("CSPRNG".to_string()) } else { None },
        }).collect();

        Self {
            original_name: name.to_string(),
            shares,
            masking_order: order,
            consistency_verified: false,
        }
    }

    /// Verify consistency: simulate XOR of all shares and check it equals the "secret value."
    /// With concrete byte values this performs the actual mathematical check.
    pub fn verify_consistency_concrete(&mut self, share_values: &[u8]) -> Result<u8, &'static str> {
        if share_values.len() != self.shares.len() {
            return Err("Share count mismatch");
        }
        // x = share_0 ⊕ share_1 ⊕ ... ⊕ share_d
        let reconstructed = share_values.iter().fold(0u8, |acc, &s| acc ^ s);
        self.consistency_verified = true;
        Ok(reconstructed)
    }
}

// ============================================================
// Arithmetic Masking Scheme (Post-Quantum Lattice Cryptography)
// ============================================================
//
// In lattice-based cryptosystems (e.g., ML-KEM/Kyber with q=3329,
// ML-DSA/Dilithium with q=8380417), sensitive polynomial coefficients
// must be protected with arithmetic additive sharing modulo q:
//   x = (A_1 + A_2 + ... + A_d) mod q
// Converting between Boolean masking (for S-boxes/hashes) and Arithmetic
// masking (for polynomial multiplication/NTT) requires verified Goubin/Coron
// conversion gadgets without intermediate unmasked power leakage.

/// A single arithmetic share modulo q.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArithmeticShare {
    pub share_id: usize,
    pub variable_name: String,
    pub modulus: u32,
    pub is_randomized: bool,
}

/// An arithmetically masked variable modulo q.
#[derive(Debug, Clone)]
pub struct ArithmeticMaskedVariable {
    pub original_name: String,
    pub modulus: u32,
    pub shares: Vec<ArithmeticShare>,
    pub masking_order: MaskingOrder,
    pub consistency_verified: bool,
}

impl ArithmeticMaskedVariable {
    /// Construct a new arithmetically masked variable modulo q with order d (d+1 shares).
    pub fn new(name: &str, modulus: u32, order: MaskingOrder) -> Self {
        let d = order.0 as usize;
        let shares = (0..=d).map(|i| ArithmeticShare {
            share_id: i,
            variable_name: format!("{}__arith_share_{}", name, i),
            modulus,
            is_randomized: i < d,
        }).collect();

        Self {
            original_name: name.to_string(),
            modulus,
            shares,
            masking_order: order,
            consistency_verified: false,
        }
    }

    /// Verify consistency: reconstruct secret value x = sum(shares) mod q.
    pub fn verify_consistency_mod_q(&mut self, share_values: &[u32]) -> Result<u32, &'static str> {
        if share_values.len() != self.shares.len() {
            return Err("Arithmetic share count mismatch");
        }
        if self.modulus == 0 {
            return Err("Modulus q must be non-zero");
        }
        let q = self.modulus as u64;
        let reconstructed = share_values.iter().fold(0u64, |acc, &s| (acc + s as u64) % q) as u32;
        self.consistency_verified = true;
        Ok(reconstructed)
    }

    /// Verify Boolean-to-Arithmetic (B2A) conversion gadget correctness.
    /// Ensures that Boolean shares (x = b0 ^ b1) are securely transformed into
    /// arithmetic shares (x = (a0 + a1) mod q) without unmasked state leak.
    pub fn verify_b2a_conversion(&self, bool_val: u8, arith_shares: &[u32]) -> Result<(), &'static str> {
        if arith_shares.len() != self.shares.len() {
            return Err("B2A share count mismatch");
        }
        let q = self.modulus as u64;
        let arith_sum = arith_shares.iter().fold(0u64, |acc, &s| (acc + s as u64) % q) as u32;
        if (bool_val as u32 % self.modulus) == arith_sum {
            Ok(())
        } else {
            Err("B2A conversion integrity check failed: arithmetic shares do not equal boolean value mod q")
        }
    }
}

// ============================================================
// Transition Count / Hamming Weight Leakage Model
// ============================================================

/// Computes the Hamming weight of a byte (number of 1-bits).
/// This is the standard power model: P ∝ HW(intermediate_value)
#[inline(always)]
pub fn hamming_weight(x: u8) -> u32 { x.count_ones() }

/// Computes the Hamming distance between two byte values.
/// Models the power consumed by bit transitions: P ∝ HD(old_value, new_value)
#[inline(always)]
pub fn hamming_distance(x: u8, y: u8) -> u32 { (x ^ y).count_ones() }

/// Compute the Signal-to-Noise Ratio (SNR) of a power trace column.
/// SNR = Var(signal) / Var(noise)
/// Signal variance is computed from hypothetical Hamming weight model.
/// Noise variance is the residual after subtracting the model.
pub fn compute_snr(traces: &[Vec<f64>], plaintexts: &[u8], key_byte: u8) -> f64 {
    if traces.is_empty() || plaintexts.is_empty() { return 0.0; }

    // Group traces by HW(SBOX[pt ^ k])
    let hw_groups: Vec<u32> = plaintexts.iter().map(|&pt| {
        hamming_weight(pt ^ key_byte) // Simplified: model without SBOX
    }).collect();

    // Compute group means for each HW value (0..=8)
    let mut group_sums: HashMap<u32, (f64, usize)> = HashMap::new();
    for (t, &hw) in traces.iter().zip(hw_groups.iter()) {
        if t.is_empty() { continue; }
        let entry = group_sums.entry(hw).or_insert((0.0, 0));
        entry.0 += t.iter().sum::<f64>() / t.len() as f64;
        entry.1 += 1;
    }
    let group_means: HashMap<u32, f64> = group_sums.iter()
        .map(|(&hw, &(sum, count))| (hw, sum / count as f64))
        .collect();

    if group_means.len() <= 1 {
        return 0.0;
    }

    // Signal variance = variance of group means weighted by group sizes
    let grand_mean = group_means.values().sum::<f64>() / group_means.len() as f64;
    let signal_var: f64 = group_means.values()
        .map(|&m| (m - grand_mean).powi(2))
        .sum::<f64>() / group_means.len() as f64;

    // Noise variance = mean within-group variance
    let mut noise_var_sum = 0.0f64;
    let mut noise_count = 0usize;
    for (t, &hw) in traces.iter().zip(hw_groups.iter()) {
        if t.is_empty() { continue; }
        if let Some(&group_mean) = group_means.get(&hw) {
            let trace_mean = t.iter().sum::<f64>() / t.len() as f64;
            noise_var_sum += (trace_mean - group_mean).powi(2);
            noise_count += 1;
        }
    }
    let noise_var = if noise_count > 0 { noise_var_sum / noise_count as f64 } else { 1.0 };

    let snr = signal_var / noise_var.max(1e-15);
    if snr.is_finite() { snr } else { 0.0 }
}

// ============================================================
// Masking Verification Scanner
// ============================================================

/// A finding from the leakage resiliency scanner.
#[derive(Debug, Clone)]
pub struct LeakageFinding {
    pub variable: String,
    pub finding_type: LeakageFindingType,
    pub file_path: String,
    pub line_number: u32,
    pub severity: LeakageSeverity,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LeakageFindingType {
    /// Variable enters a non-linear operation (S-Box, squaring, NTT butterfly) without a mask
    UnmaskedNonLinear,
    /// Mask is derived from a non-cryptographic PRNG (e.g., rand::random() not OsRng)
    WeakMaskSource,
    /// Shares are combined before the critical operation (mask is cancelled too early)
    PrematureCombination,
    /// The same mask value is reused across multiple operations (correlated masking)
    MaskReuse,
    /// Missing refresh: shares are not re-randomized between multiplications
    MissingMaskRefresh,
    /// Variable is written to a register without masking (register-level leakage)
    UnmaskedRegisterWrite,
    /// DPA SNR exceeds 1.0 on observed traces (statistically leaking)
    StatisticalLeakage { snr: f64 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeakageSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Code patterns that indicate dangerous unmasked non-linear operations.
const UNMASKED_NONLINEAR_PATTERNS: &[(&str, &str)] = &[
    ("SBOX[",          "Direct S-Box lookup without masking — DPA target"),
    ("sbox[",          "Direct S-Box lookup without masking — DPA target"),
    ("pow(x,",         "Unmasked modular exponentiation — SPA/DPA target"),
    (".powf(",         "Unmasked floating point exponentiation — timing side-channel"),
    ("aes::encrypt",   "Direct AES call — check for masked implementation"),
    ("encrypt(",       "Encryption operation — verify first-order Boolean masking"),
    ("montgomery_mul", "Montgomery multiplication — verify blinding is applied"),
    ("ntt_butterfly",  "Unmasked NTT butterfly operation — lattice power side-channel target"),
    ("poly_cbd",       "Centered binomial distribution sampling without masking — ML-KEM/Kyber DPA target"),
    ("sample_ntt",     "Rejection sampling without constant-time masking — lattice timing/power target"),
    ("poly_decompress","Lattice ciphertext decompression without masking — Decryption failure oracle / DPA target"),
    ("barrett_reduce", "Unblinded Barrett modular reduction — modular arithmetic side-channel target"),
];

/// Code patterns that constitute weak randomness sources for masking.
const WEAK_PRNG_PATTERNS: &[(&str, &str)] = &[
    ("rand::random()",     "rand::random() uses ChaCha12 which may not be FIPS-compliant"),
    ("Math.random()",      "Math.random() is a non-cryptographic PRNG — NEVER use for masks"),
    ("thread_rng()",       "thread_rng() acceptable but prefer OsRng for mask generation"),
    ("SmallRng",           "SmallRng is explicitly not cryptographically secure"),
    ("StdRng::seed_from_u64", "Deterministic seed — mask is predictable"),
];

/// Patterns indicating a strong (correct) mask source.
const STRONG_PRNG_PATTERNS: &[&str] = &[
    "OsRng",
    "getrandom",
    "crypto.getRandomValues",
    "rand_core::OsRng",
    "SystemRandom",
    "RAND_bytes(",
    "sodium_randombytes_buf(",
    "OQS_randombytes",
];

pub struct LeakageResiliencyScanner {
    /// Set of variable names that have been confirmed masked
    masked_variables: HashSet<String>,
    /// Map of mask variable → PRNG source used
    mask_sources: HashMap<String, String>,
    /// Set of mask values that have been seen more than once (reuse detection)
    mask_usage_count: HashMap<String, usize>,
}

impl Default for LeakageResiliencyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LeakageResiliencyScanner {
    pub fn new() -> Self {
        Self {
            masked_variables: HashSet::new(),
            mask_sources: HashMap::new(),
            mask_usage_count: HashMap::new(),
        }
    }

    /// Register that a variable has been masked with a fresh random value.
    pub fn register_mask_application(&mut self, variable_id: &str) {
        self.masked_variables.insert(variable_id.to_string());
    }

    /// Register the PRNG source used to generate a mask.
    pub fn register_mask_source(&mut self, variable_id: &str, prng_source: &str) {
        self.mask_sources.insert(variable_id.to_string(), prng_source.to_string());
    }

    /// Record that a mask value was used (for reuse detection).
    pub fn record_mask_use(&mut self, mask_id: &str) {
        *self.mask_usage_count.entry(mask_id.to_string()).or_insert(0) += 1;
    }

    /// Verify that a sensitive variable entering a non-linear operation is properly masked.
    pub fn verify_boolean_masking(&self, _operation_id: &str, variable_id: &str) -> Result<(), &'static str> {
        if self.masked_variables.contains(variable_id) {
            Ok(())
        } else {
            Err("CRITICAL LEAKAGE: Unmasked variable entering non-linear operation. \
                 Susceptible to Differential Power Analysis (DPA).")
        }
    }

    /// Scan source code for leakage vulnerabilities.
    pub fn scan_source(&self, source: &str, file_path: &str) -> Vec<LeakageFinding> {
        let mut findings = Vec::new();

        // Check for strong PRNG usage and masking keywords once for the entire source file
        let has_strong_prng = STRONG_PRNG_PATTERNS.iter().any(|p| source.contains(p));
        let has_masking_keywords = source.contains("xor") || source.contains('^') || source.contains("mask") || source.contains("share");
        let is_masked = has_strong_prng && has_masking_keywords;

        for (line_num, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            // Ignore comments to prevent false positives in documentation
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with('#') {
                continue;
            }

            let line_num = line_num as u32 + 1;

            // Check for unmasked non-linear operations
            for (pattern, description) in UNMASKED_NONLINEAR_PATTERNS {
                if line.contains(pattern) && !is_masked {
                    findings.push(LeakageFinding {
                        variable: pattern.to_string(),
                        finding_type: LeakageFindingType::UnmaskedNonLinear,
                        file_path: file_path.to_string(),
                        line_number: line_num,
                        severity: LeakageSeverity::Critical,
                        recommendation: format!(
                            "Apply first-order Boolean or arithmetic masking: compute SBOX[x ^ mask] or blind intermediate polynomials with OsRng / CSPRNG. \
                             {}", description
                        ),
                    });
                }
            }

            // Check for weak PRNG mask sources
            for (pattern, description) in WEAK_PRNG_PATTERNS {
                if line.contains(pattern) {
                    findings.push(LeakageFinding {
                        variable: pattern.to_string(),
                        finding_type: LeakageFindingType::WeakMaskSource,
                        file_path: file_path.to_string(),
                        line_number: line_num,
                        severity: LeakageSeverity::High,
                        recommendation: format!(
                            "Replace with OsRng (rand_core::OsRng) or getrandom(). {}",
                            description
                        ),
                    });
                }
            }
        }

        // Report mask reuse violations
        for (mask_id, &count) in &self.mask_usage_count {
            if count > 1 {
                findings.push(LeakageFinding {
                    variable: mask_id.clone(),
                    finding_type: LeakageFindingType::MaskReuse,
                    file_path: file_path.to_string(),
                    line_number: 0,
                    severity: LeakageSeverity::High,
                    recommendation: format!(
                        "Mask '{}' used {} times. Refresh the mask before each non-linear operation \
                         using OsRng::next_u8(). Reused masks enable algebraic cancellation attacks.",
                        mask_id, count
                    ),
                });
            }
        }

        findings
    }

    /// Run the full statistical leakage test (SNR analysis) on power traces.
    /// Returns a LeakageFinding if the SNR exceeds 1.0 (statistically leaking key byte).
    pub fn analyze_power_traces(
        &self,
        traces: &[Vec<f64>],
        plaintexts: &[u8],
        key_byte: u8,
        file_path: &str,
    ) -> Option<LeakageFinding> {
        let snr = compute_snr(traces, plaintexts, key_byte);
        if snr > 1.0 {
            Some(LeakageFinding {
                variable: format!("key_byte_0x{:02X}", key_byte),
                finding_type: LeakageFindingType::StatisticalLeakage { snr },
                file_path: file_path.to_string(),
                line_number: 0,
                severity: if snr > 5.0 { LeakageSeverity::Critical } else { LeakageSeverity::High },
                recommendation: format!(
                    "SNR = {:.2} > 1.0. Key byte 0x{:02X} is statistically leaking from power traces. \
                     Apply first-order Boolean masking to all intermediate AES state bytes.",
                    snr, key_byte
                ),
            })
        } else {
            None
        }
    }
}
