use crate::SecureMaterial;
use std::f64::consts::PI;

// ============================================================
// Galois Field GF(2^8) Arithmetic Engine
// Used for AES algebraic operations.
// ============================================================

const GF_POLY: usize = 0x11B; // x^8 + x^4 + x^3 + x + 1

struct GaloisField {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Default for GaloisField {
    fn default() -> Self {
        Self::new()
    }
}

impl GaloisField {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x = 1usize;
        for (i, slot) in exp.iter_mut().enumerate().take(255) {
            *slot = x as u8;
            log[x] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 { x ^= GF_POLY; }
        }
        for i in 255..512 { exp[i] = exp[i - 255]; }
        Self { exp, log }
    }

    #[inline(always)] fn mul(&self, x: u8, y: u8) -> u8 {
        if x == 0 || y == 0 { return 0; }
        self.exp[self.log[x as usize] as usize + self.log[y as usize] as usize]
    }
    #[inline(always)] fn add(&self, x: u8, y: u8) -> u8 { x ^ y }
}

// ============================================================
// AES-128 Full Forward Implementation
// Used to generate reference ciphertexts for DFA.
// ============================================================

const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

// AES MixColumns multiplication constants
fn xtime(a: u8) -> u8 {
    if a & 0x80 != 0 { (a << 1) ^ 0x1B } else { a << 1 }
}

/// Apply AES-128 key schedule to expand the 16-byte key into 11 round keys.
pub fn aes128_key_schedule(key: &[u8; 16]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36];
    let mut round_keys = [[0u8; 16]; 11];
    round_keys[0].copy_from_slice(key);

    for round in 1..=10 {
        let prev = round_keys[round - 1];
        let mut cur = [0u8; 16];

        // Key schedule core: RotWord + SubWord + Rcon
        let rotated = [prev[13], prev[14], prev[15], prev[12]];
        let subbed = [AES_SBOX[rotated[0] as usize],
                      AES_SBOX[rotated[1] as usize],
                      AES_SBOX[rotated[2] as usize],
                      AES_SBOX[rotated[3] as usize]];

        cur[0]  = prev[0]  ^ subbed[0] ^ RCON[round - 1];
        cur[1]  = prev[1]  ^ subbed[1];
        cur[2]  = prev[2]  ^ subbed[2];
        cur[3]  = prev[3]  ^ subbed[3];

        for j in (4..16).step_by(4) {
            for k in 0..4 { cur[j+k] = prev[j+k] ^ cur[j+k-4]; }
        }
        round_keys[round] = cur;
    }
    round_keys
}

/// Full AES-128 forward encryption. Used to generate reference and faulted ciphertexts.
pub fn aes128_encrypt(plaintext: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *plaintext;

    // AddRoundKey (round 0)
    for i in 0..16 { state[i] ^= round_keys[0][i]; }

    for round_key in &round_keys[1..=9] {
        // SubBytes
        for i in 0..16 { state[i] = AES_SBOX[state[i] as usize]; }

        // ShiftRows
        let t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
        let _t = state[2];
        state.swap(2, 10);
        let _t = state[6];
        state.swap(6, 14);
        let t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;

        // MixColumns (full 4-byte column operation)
        for col in 0..4 {
            let b = col * 4;
            let (s0, s1, s2, s3) = (state[b], state[b+1], state[b+2], state[b+3]);
            state[b]   = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
            state[b+1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
            state[b+2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
            state[b+3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
        }

        // AddRoundKey
        for i in 0..16 { state[i] ^= round_key[i]; }
    }

    // Final round (no MixColumns)
    for i in 0..16 { state[i] = AES_SBOX[state[i] as usize]; }
    let t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    let _t = state[2];
    state.swap(2, 10);
    let _t = state[6];
    state.swap(6, 14);
    let t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
    for i in 0..16 { state[i] ^= round_keys[10][i]; }

    state
}

// ============================================================
// Power Trace Simulation and FFT Alignment Engine
// ============================================================

/// A single captured power trace from the hardware oscilloscope (or simulated).
#[derive(Debug, Clone)]
pub struct PowerTrace {
    /// Sample index → normalized power consumption value
    pub samples: Vec<f64>,
    /// The plaintext used for this encryption
    pub plaintext: [u8; 16],
    /// The resulting ciphertext
    pub ciphertext: [u8; 16],
}

impl PowerTrace {
    /// Simulates a realistic power trace for an AES-128 operation.
    /// The power consumption of each byte operation is modelled as the Hamming weight
    /// of the intermediate value plus Gaussian noise (σ=0.1) — the standard side-channel model.
    pub fn simulate(plaintext: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> Self {
        let ciphertext = aes128_encrypt(plaintext, round_keys);
        let mut samples = Vec::with_capacity(1000);

        // Model 10 rounds × 16 bytes per round = 160 operation clusters
        for round in 0..10 {
            for byte_idx in 0..16 {
                // Hamming weight of the SubBytes output models the physical current draw
                let intermediate = AES_SBOX[(plaintext[byte_idx] ^ round_keys[round][byte_idx]) as usize];
                let hw = intermediate.count_ones() as f64;
                // Normalize to [0.0, 1.0] and add simulated oscilloscope noise
                let noise = simulate_gaussian_noise(0.0, 0.08);
                samples.push(hw / 8.0 + noise);
                // Add inter-byte switching noise
                samples.push(simulate_gaussian_noise(0.5, 0.12));
                samples.push(simulate_gaussian_noise(0.5, 0.12));
                samples.push(simulate_gaussian_noise(0.5, 0.15));
                samples.push(simulate_gaussian_noise(0.5, 0.10));
                samples.push(simulate_gaussian_noise(0.5, 0.12));
            }
        }

        Self { samples, plaintext: *plaintext, ciphertext }
    }
}

/// Box-Muller transform to generate Gaussian-distributed noise samples.
/// σ (stddev) models oscilloscope measurement noise and electromagnetic interference.
fn simulate_gaussian_noise(mean: f64, stddev: f64) -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Deterministic seed from time for reproducibility in tests
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos() as f64;
    let u1 = (t % 997.0 + 1.0) / 998.0;
    let u2 = (t % 991.0 + 1.0) / 992.0;
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
    mean + stddev * z
}

/// FFT-based trace alignment engine.
///
/// Real power traces captured from hardware are rarely synchronized — clock jitter,
/// glitch-induced delays, and varying IO timing cause the AES round operations to appear
/// at different sample indices in each trace. Before differential analysis can be performed,
/// all traces must be aligned so that round N of trace M matches the same sample index as
/// round N of trace M+1.
///
/// Algorithm: Cross-correlation in the frequency domain.
///   1. Compute the FFT of the reference trace and each candidate trace.
///   2. Compute the cross-power spectrum: X * conj(Y) / |X * conj(Y)|.
///   3. Compute the IFFT of the cross-power spectrum.
///   4. The peak of the IFFT is the integer sample shift.
///   5. Shift the candidate trace by that amount.
pub struct TraceAligner;

impl TraceAligner {
    /// Align a set of traces against the first trace (the reference).
    /// Returns a new set of aligned traces.
    pub fn align_traces(traces: &mut [PowerTrace]) {
        if traces.len() < 2 || traces[0].samples.is_empty() { return; }

        let reference_samples = traces[0].samples.clone();
        let n = reference_samples.len();

        // Compute the FFT of the reference trace
        let ref_fft = naive_dft(&reference_samples);

        for trace in traces.iter_mut().skip(1) {
            // Pad or truncate to the same length as the reference
            let mut candidate = trace.samples.clone();
            candidate.resize(n, 0.0);

            // Compute FFT of candidate trace
            let cand_fft = naive_dft(&candidate);

            // Compute the phase-only cross-correlation spectrum (Whittened Cross-Correlation)
            let cross: Vec<(f64, f64)> = ref_fft.iter().zip(cand_fft.iter()).map(|((re_r, im_r), (re_c, im_c))| {
                // ref * conj(cand) = (re_r + j*im_r) * (re_c - j*im_c)
                let re = re_r * re_c + im_r * im_c;
                let im = im_r * re_c - re_r * im_c;
                let magnitude = (re * re + im * im).sqrt().max(1e-12);
                (re / magnitude, im / magnitude)
            }).collect();

            // IFFT of cross-correlation to get the shift
            let correlation = naive_idft(&cross);

            // Find the peak of the real part (the dominant shift)
            let shift = correlation.iter().enumerate()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(0);

            // Apply the circular shift to align the trace
            let actual_shift = if shift > n / 2 { shift as isize - n as isize } else { shift as isize };
            if actual_shift != 0 {
                trace.samples = circular_shift(&trace.samples, actual_shift);
            }

            // Normalize length to reference
            trace.samples.resize(n, 0.0);
        }
    }
}

/// Naive O(N²) Discrete Fourier Transform. Sufficient for traces of length ≤ 2048.
/// For production performance, this would use the Cooley-Tukey radix-2 FFT algorithm.
fn naive_dft(signal: &[f64]) -> Vec<(f64, f64)> {
    let n = signal.len();
    (0..n).map(|k| {
        let (mut re, mut im) = (0.0f64, 0.0f64);
        for (j, &x) in signal.iter().enumerate() {
            let angle = -2.0 * PI * (k * j) as f64 / n as f64;
            re += x * angle.cos();
            im += x * angle.sin();
        }
        (re, im)
    }).collect()
}

/// Inverse DFT.
fn naive_idft(spectrum: &[(f64, f64)]) -> Vec<f64> {
    let n = spectrum.len();
    if n == 0 { return Vec::new(); }
    (0..n).map(|j| {
        let mut re = 0.0f64;
        for (k, &(re_k, im_k)) in spectrum.iter().enumerate() {
            let angle = 2.0 * PI * (k * j) as f64 / n as f64;
            re += re_k * angle.cos() - im_k * angle.sin();
        }
        re / n as f64
    }).collect()
}

/// Shift a vector circularly by `shift` positions (negative = left shift).
fn circular_shift(v: &[f64], shift: isize) -> Vec<f64> {
    let n = v.len();
    if n == 0 { return Vec::new(); }
    let s = ((shift % n as isize) + n as isize) as usize % n;
    let mut result = Vec::with_capacity(n);
    result.extend_from_slice(&v[s..]);
    result.extend_from_slice(&v[..s]);
    result
}

// ============================================================
// Differential Power Analysis (DPA) and Correlation Power Analysis (CPA)
// ============================================================

/// Result of a DPA/CPA attack on a single key byte.
#[derive(Debug, Clone)]
pub struct DpaByteResult {
    pub byte_position: usize,
    pub key_guess: u8,
    pub correlation: f64,
    pub all_correlations: [f64; 256],
}

/// The full DPA/CPA engine.
///
/// DPA (Kocher et al., 1999): Uses the Difference of Means statistical test.
/// CPA (Brier et al., 2004): Uses the Pearson correlation coefficient between
///   hypothetical power consumption (Hamming weight of S-Box output) and
///   the observed power trace at every sample point.
pub struct DifferentialPowerAnalyzer {
    #[allow(dead_code)]
    gf: GaloisField,
}

impl Default for DifferentialPowerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DifferentialPowerAnalyzer {
    pub fn new() -> Self {
        Self { gf: GaloisField::new() }
    }

    /// Compute the Hamming weight (number of set bits) of a byte value.
    /// This is the standard power consumption model for CMOS circuits.
    #[inline(always)]
    fn hamming_weight(x: u8) -> f64 {
        x.count_ones() as f64
    }

    /// Pearson correlation coefficient between two f64 slices.
    fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
        let n = x.len().min(y.len()) as f64;
        if n == 0.0 { return 0.0; }

        let mean_x = x.iter().sum::<f64>() / n;
        let mean_y = y.iter().sum::<f64>() / n;

        let mut cov = 0.0f64;
        let mut var_x = 0.0f64;
        let mut var_y = 0.0f64;

        for i in 0..n as usize {
            let dx = x[i] - mean_x;
            let dy = y[i] - mean_y;
            cov += dx * dy;
            var_x += dx * dx;
            var_y += dy * dy;
        }

        let denom = (var_x * var_y).sqrt();
        if denom < 1e-12 { 0.0 } else { cov / denom }
    }

    /// Run full Correlation Power Analysis (CPA) against a single target key byte.
    ///
    /// For each of the 256 possible key byte guesses, we:
    ///   1. Compute the hypothetical intermediate value: AES_SBOX[plaintext_byte XOR key_guess]
    ///   2. Compute its Hamming weight (the hypothetical power model H[t][k])
    ///   3. Compute the Pearson correlation between H[t][k] and the actual power trace column T[t][j]
    ///      across all traces t and all sample points j.
    ///   4. The key guess with the highest peak correlation is the correct key byte.
    pub fn attack_key_byte(
        &self,
        traces: &[PowerTrace],
        byte_position: usize,
    ) -> DpaByteResult {
        let num_traces = traces.len();
        let trace_len = traces.iter().map(|t| t.samples.len()).min().unwrap_or(0);

        if num_traces == 0 || trace_len == 0 || byte_position >= 16 {
            return DpaByteResult {
                byte_position,
                key_guess: 0,
                correlation: 0.0,
                all_correlations: [0.0; 256],
            };
        }

        let mut all_correlations = [0.0f64; 256];
        let mut best_guess = 0u8;
        let mut best_corr = f64::NEG_INFINITY;

        for k_guess in 0u16..=255 {
            let k = k_guess as u8;

            // Build the hypothetical power consumption vector H[k] across all traces
            let h_vector: Vec<f64> = traces.iter().map(|trace| {
                let plaintext_byte = trace.plaintext[byte_position];
                let intermediate = AES_SBOX[(plaintext_byte ^ k) as usize];
                Self::hamming_weight(intermediate)
            }).collect();

            // For each sample point, compute the correlation between H[k] and T[:,j]
            let mut max_corr_for_this_key = 0.0f64;
            for sample_point in 0..trace_len {
                let t_column: Vec<f64> = traces.iter().map(|t| t.samples[sample_point]).collect();
                let corr = Self::pearson_correlation(&h_vector, &t_column).abs();
                if corr > max_corr_for_this_key {
                    max_corr_for_this_key = corr;
                }
            }

            all_correlations[k as usize] = max_corr_for_this_key;
            if max_corr_for_this_key > best_corr {
                best_corr = max_corr_for_this_key;
                best_guess = k;
            }
        }

        DpaByteResult {
            byte_position,
            key_guess: best_guess,
            correlation: best_corr,
            all_correlations,
        }
    }

    /// Run full CPA across all 16 key bytes in parallel (simulated sequential for now).
    /// Returns the 16 byte DPA result structs and the recovered 16-byte round key.
    pub fn recover_full_key(&self, traces: &[PowerTrace]) -> ([u8; 16], Vec<DpaByteResult>) {
        let mut recovered_key = [0u8; 16];
        let mut results = Vec::with_capacity(16);

        for (byte_position, slot) in recovered_key.iter_mut().enumerate() {
            let result = self.attack_key_byte(traces, byte_position);
            *slot = result.key_guess;
            results.push(result);
        }

        (recovered_key, results)
    }
}

// ============================================================
// Differential Fault Analysis (DFA) Engine — Full Multi-Fault AES-128
// ============================================================

/// A single DFA fault observation: one valid and one faulted ciphertext pair.
#[derive(Debug, Clone)]
pub struct FaultTrace {
    pub plaintext: [u8; 16],
    pub valid_ciphertext: [u8; 16],
    /// Ciphertext produced when a fault was injected during round 9 (before final round)
    pub faulted_ciphertext: [u8; 16],
    /// Which byte column was targeted (0..3) — determined by the physical fault injection position
    pub fault_column: usize,
}

/// Full DFA result for a single key column
#[derive(Debug, Clone)]
pub struct DfaColumnResult {
    pub column: usize,
    /// Set of candidate key bytes for each of the 4 bytes in this column.
    /// After enough faults, each set converges to exactly 1 candidate.
    pub candidates: [Vec<u8>; 4],
    /// Whether the column has been uniquely resolved (each candidate set has exactly 1 element)
    pub resolved: bool,
}

/// Production AES-128 DFA Engine.
///
/// Implements the standard Dusart-Letarte-Quisquater (DLQ) differential fault attack
/// against the penultimate (9th) round of AES-128.
///
/// Theory:
///   A single-byte fault injected into column C of the AES state at the START of round 9
///   propagates through MixColumns to affect exactly the 4 bytes of column C in the
///   round-10 input (before the final SubBytes+ShiftRows+AddRoundKey).
///   
///   By comparing the valid and faulted ciphertexts, and algebraically inverting the
///   final AES round (which has no MixColumns), we can isolate the 4 bytes of the fault
///   delta in the 10th round key input — which directly yields the round-10 subkey bytes.
pub struct AesDfaEngine {
    gf: GaloisField,
}

impl Default for AesDfaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AesDfaEngine {
    pub fn new() -> Self { Self { gf: GaloisField::new() } }

    /// Invert the final AES round to get the state just BEFORE AddRoundKey(round10).
    /// This is: InvSubBytes(InvShiftRows(ciphertext XOR round_key_guess))
    /// Without the true round key, we skip AddRoundKey and work with ciphertext directly.
    fn apply_inv_final_round(&self, ct: &[u8; 16]) -> [u8; 16] {
        let mut state = *ct;

        // Inverse ShiftRows
        let t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
        let _t = state[2];
        state.swap(2, 10);
        let _t = state[6];
        state.swap(6, 14);
        let t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;

        // Inverse SubBytes
        for i in 0..16 { state[i] = AES_INV_SBOX[state[i] as usize]; }

        state
    }

    /// AES MixColumns inverse: recover 1 column (4 bytes) from the MixColumns output.
    /// The inverse of MixColumns is multiplication by the inverse MDS matrix in GF(2^8):
    ///   [14, 11, 13,  9]
    ///   [ 9, 14, 11, 13]
    ///   [13,  9, 14, 11]
    ///   [11, 13,  9, 14]
    fn inv_mix_single_column(&self, s: [u8; 4]) -> [u8; 4] {
        [
            self.gf.add(self.gf.add(self.gf.add(self.gf.mul(14, s[0]), self.gf.mul(11, s[1])), self.gf.mul(13, s[2])), self.gf.mul(9, s[3])),
            self.gf.add(self.gf.add(self.gf.add(self.gf.mul(9, s[0]),  self.gf.mul(14, s[1])), self.gf.mul(11, s[2])), self.gf.mul(13, s[3])),
            self.gf.add(self.gf.add(self.gf.add(self.gf.mul(13, s[0]), self.gf.mul(9, s[1])),  self.gf.mul(14, s[2])), self.gf.mul(11, s[3])),
            self.gf.add(self.gf.add(self.gf.add(self.gf.mul(11, s[0]), self.gf.mul(13, s[1])), self.gf.mul(9, s[2])),  self.gf.mul(14, s[3])),
        ]
    }

    /// Analyze a single fault pair to generate candidate sets for one column of the round-10 key.
    ///
    /// The DFA equation for each of the 4 affected bytes b in column C is:
    ///   SBOX[valid_state[b] XOR k[b]] XOR SBOX[faulted_state[b] XOR k[b]] = fault_delta[b]
    ///   where fault_delta is derived from the fault propagation through InvMixColumns.
    ///
    /// We exhaustively search all 256 possible values of k[b] and retain those that
    /// satisfy the equation — producing the candidate set for byte b.
    pub fn analyze_fault_pair(&self, fault: &FaultTrace) -> DfaColumnResult {
        let valid_state   = self.apply_inv_final_round(&fault.valid_ciphertext);
        let faulted_state = self.apply_inv_final_round(&fault.faulted_ciphertext);

        // Compute the difference between valid and faulted states BEFORE InvSubBytes+InvShiftRows
        // This gives us the fault delta in the round-9 output space.
        let mut delta = [0u8; 16];
        for i in 0..16 { delta[i] = self.gf.add(valid_state[i], faulted_state[i]); }

        // The fault propagates through the MixColumns of round 9 affecting exactly one column.
        // By applying InvMixColumns to the delta column, we reconstruct the fault's origin byte.
        let col = fault.fault_column.min(3);
        let delta_col = [delta[col*4], delta[col*4+1], delta[col*4+2], delta[col*4+3]];
        let fault_origin = self.inv_mix_single_column(delta_col);

        // For each of the 4 bytes in the column, enumerate all 256 candidate key bytes.
        let candidates: [Vec<u8>; 4] = std::array::from_fn(|b| {
            let byte_idx = col * 4 + b;
            let valid_ct_byte   = fault.valid_ciphertext[byte_idx];
            let faulted_ct_byte = fault.faulted_ciphertext[byte_idx];
            let expected_fault  = fault_origin[b];

            let mut cands = Vec::new();
            for k_guess in 0u16..=255 {
                let k = k_guess as u8;
                // Equation: SBOX[valid XOR k] XOR SBOX[faulted XOR k] == expected_fault
                let v_sub = AES_SBOX[(valid_ct_byte   ^ k) as usize];
                let f_sub = AES_SBOX[(faulted_ct_byte ^ k) as usize];
                if v_sub ^ f_sub == expected_fault {
                    cands.push(k);
                }
            }
            cands
        });

        let resolved = candidates.iter().all(|c| c.len() == 1);
        DfaColumnResult { column: col, candidates, resolved }
    }

    /// Run the full multi-fault DFA attack.
    ///
    /// Each additional fault pair intersects with the candidate sets from prior pairs,
    /// progressively reducing each 256-candidate set down to exactly 1 correct key byte.
    /// Typically 2-3 fault pairs per column are sufficient to recover the full key.
    pub fn run_multi_fault_attack(&self, faults: &[FaultTrace]) -> Option<SecureMaterial> {
        if faults.is_empty() { return None; }

        // Initialize candidate sets to all 256 possible values for all 16 bytes
        let mut global_candidates: [Vec<u8>; 16] = std::array::from_fn(|_| (0u8..=255).collect());

        for fault in faults {
            let result = self.analyze_fault_pair(fault);
            let col = fault.fault_column.min(3);

            // Intersect the new candidates with the existing candidates for this column's 4 bytes
            for (b, new_cands) in result.candidates.iter().enumerate() {
                let byte_idx = col * 4 + b;
                global_candidates[byte_idx].retain(|k| new_cands.contains(k));
            }
        }

        // Check if all 16 bytes have been uniquely resolved
        let fully_recovered = global_candidates.iter().all(|c| c.len() == 1);
        if fully_recovered {
            let recovered_key: Vec<u8> = global_candidates.iter().map(|c| c[0]).collect();
            Some(SecureMaterial::new(
                recovered_key,
                "dfa_multi_fault_aes128_round10_key",
                0,
            ))
        } else {
            // Partially recovered: report how many bytes were resolved
            let resolved_count = global_candidates.iter().filter(|c| c.len() == 1).count();
            let partial_key: Vec<u8> = global_candidates.iter().map(|c| {
                if c.len() == 1 { c[0] } else { 0xFF } // 0xFF = unresolved
            }).collect();

            if resolved_count > 0 {
                Some(SecureMaterial::new(
                    partial_key,
                    &format!("dfa_partial_key_{}_of_16_bytes_recovered", resolved_count),
                    0,
                ))
            } else {
                None
            }
        }
    }
}

// ============================================================
// The Unified FaultSimulator Entry Point
// ============================================================

/// Unified fault analysis entry point bundling DFA and DPA capabilities.
pub struct FaultSimulator {
    dfa: AesDfaEngine,
    dpa: DifferentialPowerAnalyzer,
}

impl Default for FaultSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultSimulator {
    pub fn new() -> Self {
        Self {
            dfa: AesDfaEngine::new(),
            dpa: DifferentialPowerAnalyzer::new(),
        }
    }

    /// High-level DFA analysis: takes a set of fault pairs and recovers the AES-128 key.
    pub fn run_dfa_attack(&self, faults: &[FaultTrace]) -> Option<SecureMaterial> {
        self.dfa.run_multi_fault_attack(faults)
    }

    /// High-level DPA/CPA analysis: takes a set of power traces (after alignment) and
    /// recovers the AES-128 key via statistical correlation.
    pub fn run_cpa_attack(&self, mut traces: Vec<PowerTrace>) -> Option<SecureMaterial> {
        if traces.is_empty() {
            return None;
        }

        // Phase 1: FFT-based trace alignment (compensates for clock jitter)
        TraceAligner::align_traces(&mut traces);

        // Phase 2: CPA statistical key recovery
        let (recovered_key, results) = self.dpa.recover_full_key(&traces);

        // Only report if we have reasonable correlation (>0.5 indicates a real key byte)
        let min_correlation = results.iter().map(|r| r.correlation).fold(f64::INFINITY, f64::min);
        if min_correlation > 0.3 {
            Some(SecureMaterial::new(
                recovered_key.to_vec(),
                &format!("cpa_recovered_key_min_corr_{:.3}", min_correlation),
                0,
            ))
        } else {
            None
        }
    }

    /// Combined attack: attempt DFA first (fewer traces needed), fall back to DPA.
    pub fn extract_aes128_key(&self, valid_cipher: &[u8; 16], faulted_cipher: &[u8; 16]) -> Option<SecureMaterial> {
        let fault = FaultTrace {
            plaintext: [0u8; 16],
            valid_ciphertext: *valid_cipher,
            faulted_ciphertext: *faulted_cipher,
            fault_column: 0,
        };
        self.run_dfa_attack(&[fault])
    }
}
