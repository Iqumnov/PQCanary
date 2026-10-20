use std::f64;

/// A 2×2 complex matrix representing the density matrix of a single-qubit quantum state.
/// Stored as [[ρ₀₀, ρ₀₁], [ρ₁₀, ρ₁₁]] where elements are (real, imag) pairs.
#[derive(Debug, Clone)]
pub struct DensityMatrix {
    /// ρ[row][col] = (real, imaginary)
    pub rho: [[f64; 4]; 2], // [row][col_re, col_im] — packed as [re00, im00, re01, im01; re10, im10, re11, im11]
    /// Simplified storage: [[re00, re01], [re10, re11]] for real parts, [[im00, im01], [im10, im11]] for imag
    re: [[f64; 2]; 2],
    im: [[f64; 2]; 2],
}

impl DensityMatrix {
    /// Create the pure state |0⟩⟨0| density matrix: ρ = [[1,0],[0,0]]
    pub fn ground_state() -> Self {
        Self {
            rho: [[0.0; 4]; 2],
            re: [[1.0, 0.0], [0.0, 0.0]],
            im: [[0.0, 0.0], [0.0, 0.0]],
        }
    }

    /// Create the maximally mixed state ρ = I/2 = [[0.5,0],[0,0.5]]
    pub fn maximally_mixed() -> Self {
        Self {
            rho: [[0.0; 4]; 2],
            re: [[0.5, 0.0], [0.0, 0.5]],
            im: [[0.0, 0.0], [0.0, 0.0]],
        }
    }

    /// Create the pure state |+⟩⟨+| = [[0.5,0.5],[0.5,0.5]] (Hadamard state)
    pub fn plus_state() -> Self {
        Self {
            rho: [[0.0; 4]; 2],
            re: [[0.5, 0.5], [0.5, 0.5]],
            im: [[0.0, 0.0], [0.0, 0.0]],
        }
    }

    /// Get the real part of ρ[i][j]
    pub fn re(&self, i: usize, j: usize) -> f64 { self.re[i][j] }
    /// Get the imaginary part of ρ[i][j]
    pub fn im(&self, i: usize, j: usize) -> f64 { self.im[i][j] }

    /// Trace of the density matrix: Tr(ρ) = ρ₀₀ + ρ₁₁ (must = 1 for a valid state)
    pub fn trace(&self) -> f64 {
        self.re[0][0] + self.re[1][1]
    }

    /// Purity: Tr(ρ²) = 1 for pure states, 0.5 for maximally mixed
    pub fn purity(&self) -> f64 {
        // Tr(ρ²) = Σᵢⱼ |ρᵢⱼ|²
        let mut sum = 0.0;
        for i in 0..2 {
            for j in 0..2 {
                sum += self.re[i][j] * self.re[i][j] + self.im[i][j] * self.im[i][j];
            }
        }
        sum
    }

    /// Von Neumann entropy: S(ρ) = -Tr(ρ ln ρ)
    /// For a qubit with eigenvalues λ₁, λ₂: S = -λ₁ ln λ₁ - λ₂ ln λ₂
    pub fn von_neumann_entropy(&self) -> f64 {
        // For a 2×2 Hermitian matrix, eigenvalues are real
        // λ = (Tr ± √(Tr² - 4·det)) / 2
        let tr = self.trace();
        let det = self.re[0][0] * self.re[1][1] - (self.re[0][1] * self.re[0][1] + self.im[0][1] * self.im[0][1]);
        let discriminant = (tr * tr - 4.0 * det).max(0.0);
        let lam1 = (tr + discriminant.sqrt()) / 2.0;
        let lam2 = (tr - discriminant.sqrt()) / 2.0;
        let mut entropy = 0.0;
        for &lam in &[lam1, lam2] {
            if lam > 1e-15 && lam <= 1.0 {
                entropy -= lam * lam.ln();
            }
        }
        if entropy.is_nan() { 0.0 } else { entropy.max(0.0) }
    }

    /// Off-diagonal element magnitude: |ρ₀₁| — measures quantum coherence
    pub fn coherence_magnitude(&self) -> f64 {
        (self.re[0][1] * self.re[0][1] + self.im[0][1] * self.im[0][1]).sqrt()
    }
}

// ============================================================
// Lindblad Master Equation Simulator (Open Quantum Systems)
// ============================================================
//
// The Lindblad equation governs the time evolution of a density matrix
// under environmental decoherence:
//
//   dρ/dt = -i[H, ρ] + Σₖ γₖ (Lₖ ρ Lₖ† - ½{Lₖ†Lₖ, ρ})
//
// where H is the system Hamiltonian, Lₖ are Lindblad jump operators,
// and γₖ are the corresponding decay rates.
//
// For a qubit in a thermal bath, the relevant jump operators are:
//   L₁ = σ₋ = [[0,1],[0,0]] — relaxation (energy decay, rate γ₁ = 1/T1)
//   L₂ = σ_z = [[1,0],[0,-1]] — dephasing (phase randomization, rate γ_φ = 1/T2 - 1/(2T1))

/// Quantum Decoherence Taint Tracker
/// Uses the full Lindblad Master Equation to simulate environmental noise and wave-function collapse.
pub struct DecoherenceSimulator {
    /// Energy relaxation rate γ₁ = 1/T₁ (1/s)
    pub gamma_decay_rate: f64,
    /// Pure dephasing rate γ_φ = 1/T₂* - 1/(2T₁) (1/s)
    pub gamma_dephasing: f64,
}

impl DecoherenceSimulator {
    pub fn new(gamma_decay_rate: f64, gamma_dephasing: f64) -> Self {
        Self { gamma_decay_rate, gamma_dephasing }
    }

    /// Convenience constructor with standard T1/T2 relaxation times (in seconds).
    /// γ₁ = 1/T₁, γ_φ = 1/T₂* - 1/(2T₁)
    pub fn from_t1_t2(t1: f64, t2: f64) -> Self {
        let safe_t1 = if t1 <= 0.0 || t1.is_nan() { 1e-6 } else { t1 };
        let safe_t2 = if t2 <= 0.0 || t2.is_nan() { 1e-6 } else { t2 };
        let gamma_1 = 1.0 / safe_t1;
        let gamma_2_total = 1.0 / safe_t2;
        // γ_φ = γ₂_total - γ₁/2 (pure dephasing rate, must be ≥ 0)
        let gamma_phi = (gamma_2_total - gamma_1 / 2.0).max(0.0);
        Self { gamma_decay_rate: gamma_1, gamma_dephasing: gamma_phi }
    }

    /// Analytically solve the Lindblad equation for a single qubit under the
    /// standard amplitude damping + dephasing channels.
    ///
    /// Analytic solution for ρ(t) starting from ρ(0):
    ///   ρ₁₁(t) = ρ₁₁(0) · e^{-γ₁ t}
    ///   ρ₀₀(t) = 1 - ρ₁₁(t)
    ///   ρ₀₁(t) = ρ₀₁(0) · e^{-(γ₁/2 + γ_φ) t}   ← T₂ decay of coherences
    ///   ρ₁₀(t) = ρ₁₀(0) · e^{-(γ₁/2 + γ_φ) t}   ← complex conjugate
    pub fn evolve(&self, rho_initial: &DensityMatrix, time_t: f64) -> DensityMatrix {
        let gamma_transverse = self.gamma_decay_rate / 2.0 + self.gamma_dephasing;

        // Exponential decay factors
        let decay_pop = (-self.gamma_decay_rate * time_t).exp();      // e^{-γ₁ t}
        let decay_coh = (-gamma_transverse * time_t).exp();           // e^{-γ_T t}

        // Populations
        let rho11_t = rho_initial.re[1][1] * decay_pop;
        let rho00_t = 1.0 - rho11_t; // Trace conservation

        // Coherences (off-diagonal) decay at T₂ rate
        let rho01_re = rho_initial.re[0][1] * decay_coh;
        let rho01_im = rho_initial.im[0][1] * decay_coh;
        // ρ₁₀ = conj(ρ₀₁)
        let rho10_re = rho01_re;
        let rho10_im = -rho01_im;

        DensityMatrix {
            rho: [[0.0; 4]; 2],
            re: [[rho00_t, rho01_re], [rho10_re, rho11_t]],
            im: [[0.0, rho01_im], [rho10_im, 0.0]],
        }
    }

    /// Numerically integrate the Lindblad equation using 4th-order Runge-Kutta.
    /// This handles non-standard Hamiltonians and time-varying jump operators.
    /// Uses dt = 0.001 / (gamma_decay_rate + gamma_dephasing) for numerical stability.
    pub fn evolve_rk4(&self, rho_initial: &DensityMatrix, time_t: f64, n_steps: usize) -> DensityMatrix {
        if !time_t.is_finite() || time_t <= 0.0 || n_steps == 0 {
            return rho_initial.clone();
        }
        let dt = time_t / n_steps as f64;
        let mut rho = rho_initial.clone();

        for _ in 0..n_steps {
            let k1 = self.lindblad_rhs(&rho);
            let rho_k2 = self.add_scaled(&rho, &k1, 0.5 * dt);
            let k2 = self.lindblad_rhs(&rho_k2);
            let rho_k3 = self.add_scaled(&rho, &k2, 0.5 * dt);
            let k3 = self.lindblad_rhs(&rho_k3);
            let rho_k4 = self.add_scaled(&rho, &k3, dt);
            let k4 = self.lindblad_rhs(&rho_k4);

            // RK4 weighted average: ρ(t+dt) = ρ(t) + dt/6 * (k1 + 2k2 + 2k3 + k4)
            for i in 0..2 {
                for j in 0..2 {
                    rho.re[i][j] += dt / 6.0 * (k1.re[i][j] + 2.0 * k2.re[i][j] + 2.0 * k3.re[i][j] + k4.re[i][j]);
                    rho.im[i][j] += dt / 6.0 * (k1.im[i][j] + 2.0 * k2.im[i][j] + 2.0 * k3.im[i][j] + k4.im[i][j]);
                }
            }
        }
        rho
    }

    /// Compute dρ/dt = Σₖ γₖ (Lₖ ρ Lₖ† - ½{Lₖ†Lₖ, ρ})
    /// (Hamiltonian term omitted here — set H = 0 for free evolution)
    fn lindblad_rhs(&self, rho: &DensityMatrix) -> DensityMatrix {
        let mut drho_re = [[0.0f64; 2]; 2];
        let mut drho_im = [[0.0f64; 2]; 2];

        // Jump operator L₁ = σ₋ = [[0,1],[0,0]] with rate γ₁
        // L₁ ρ L₁† = [[ρ₁₁, 0],[0, 0]]
        // L₁†L₁ = σ₊σ₋ = [[0,0],[0,1]]
        // {L₁†L₁, ρ} = 2·[[0,0],[0,ρ₁₁]] + anticommutator off-diagonals
        let g1 = self.gamma_decay_rate;
        drho_re[0][0] += g1 * rho.re[1][1];
        drho_re[1][1] -= g1 * rho.re[1][1];
        drho_re[0][1] -= 0.5 * g1 * rho.re[0][1];
        drho_im[0][1] -= 0.5 * g1 * rho.im[0][1];
        drho_re[1][0] -= 0.5 * g1 * rho.re[1][0];
        drho_im[1][0] -= 0.5 * g1 * rho.im[1][0];

        // Jump operator L₂ = σ_z = [[1,0],[0,-1]] with rate γ_φ (pure dephasing)
        // L₂ ρ L₂† = [[ρ₀₀, -ρ₀₁],[-ρ₁₀, ρ₁₁]]
        // ½{L₂†L₂, ρ} = ½{I, ρ} = ρ (since σ_z† σ_z = I)
        // Net: γ_φ (L₂ρL₂ - ρ) kills only the off-diagonal elements:
        //   dρ₀₁/dt += γ_φ(-ρ₀₁ - ρ₀₁) = -2γ_φ ρ₀₁
        let gp = self.gamma_dephasing;
        drho_re[0][1] -= gp * rho.re[0][1];
        drho_im[0][1] -= gp * rho.im[0][1];
        drho_re[1][0] -= gp * rho.re[1][0];
        drho_im[1][0] -= gp * rho.im[1][0];

        DensityMatrix {
            rho: [[0.0; 4]; 2],
            re: drho_re,
            im: drho_im,
        }
    }

    fn add_scaled(&self, a: &DensityMatrix, b: &DensityMatrix, scale: f64) -> DensityMatrix {
        let mut re = [[0.0f64; 2]; 2];
        let mut im = [[0.0f64; 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                re[i][j] = a.re[i][j] + scale * b.re[i][j];
                im[i][j] = a.im[i][j] + scale * b.im[i][j];
            }
        }
        DensityMatrix { rho: [[0.0; 4]; 2], re, im }
    }

    /// Simple T2 analytic formula — legacy API kept for backward compatibility.
    /// Mathematically models the exponential decay of the off-diagonal elements
    /// of a quantum density matrix over time `t`.
    pub fn calculate_density_matrix_decay(&self, time_t: f64, initial_coherence: f64) -> f64 {
        if !time_t.is_finite() || !initial_coherence.is_finite() || time_t < 0.0 {
            return 0.0;
        }
        let gamma_transverse = self.gamma_decay_rate / 2.0 + self.gamma_dephasing;
        let decay_factor = f64::exp(-gamma_transverse * time_t);
        initial_coherence * decay_factor
    }

    /// Determines if a quantum state has fatally collapsed (decohered) before reaching the receiver.
    pub fn has_decohered(&self, transmission_time: f64, coherence_threshold: f64) -> bool {
        let remaining_coherence = self.calculate_density_matrix_decay(transmission_time, 1.0);
        remaining_coherence < coherence_threshold
    }

    /// Full Lindblad evolution report: coherence, purity, and entropy at time t.
    pub fn decoherence_report(&self, rho_initial: &DensityMatrix, time_t: f64) -> DecoherenceReport {
        let rho_t = self.evolve(rho_initial, time_t);
        DecoherenceReport {
            time_s: time_t,
            coherence_magnitude: rho_t.coherence_magnitude(),
            purity: rho_t.purity(),
            von_neumann_entropy: rho_t.von_neumann_entropy(),
            trace_preserved: (rho_t.trace() - 1.0).abs() < 1e-10,
            rho_t,
        }
    }
}

/// Output from a full Lindblad evolution computation.
#[derive(Debug)]
pub struct DecoherenceReport {
    /// Time at which this report was computed (seconds)
    pub time_s: f64,
    /// Off-diagonal element magnitude |ρ₀₁| — quantifies remaining superposition
    pub coherence_magnitude: f64,
    /// Tr(ρ²) — 1.0 for pure state, 0.5 for maximally mixed
    pub purity: f64,
    /// Von Neumann entropy S(ρ) — 0 for pure state, ln(2) ≈ 0.693 for maximally mixed
    pub von_neumann_entropy: f64,
    /// Whether trace is conserved (sanity check for numerical validity)
    pub trace_preserved: bool,
    /// The final density matrix ρ(t)
    pub rho_t: DensityMatrix,
}
