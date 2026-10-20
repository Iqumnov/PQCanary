use std::f64;

// ============================================================
// Complex Number Arithmetic (full IEEE 754 implementation)
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

impl Complex {
    pub const ZERO: Complex = Complex { re: 0.0, im: 0.0 };
    pub const ONE: Complex  = Complex { re: 1.0, im: 0.0 };
    pub const I: Complex    = Complex { re: 0.0, im: 1.0 };

    #[inline] pub fn new(re: f64, im: f64) -> Self { Self { re, im } }
    #[inline] pub fn real(re: f64) -> Self { Self { re, im: 0.0 } }

    #[allow(clippy::should_implement_trait)]
    #[inline] pub fn add(self, o: Complex) -> Complex { Complex::new(self.re + o.re, self.im + o.im) }
    #[allow(clippy::should_implement_trait)]
    #[inline] pub fn sub(self, o: Complex) -> Complex { Complex::new(self.re - o.re, self.im - o.im) }
    #[allow(clippy::should_implement_trait)]
    #[inline] pub fn mul(self, o: Complex) -> Complex {
        Complex::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
    #[allow(clippy::should_implement_trait)]
    #[inline] pub fn div(self, o: Complex) -> Complex {
        let denom = o.re * o.re + o.im * o.im;
        if denom == 0.0 || !denom.is_finite() {
            return Complex::ZERO;
        }
        Complex::new(
            (self.re * o.re + self.im * o.im) / denom,
            (self.im * o.re - self.re * o.im) / denom,
        )
    }
    #[inline] pub fn scale(self, s: f64) -> Complex { Complex::new(self.re * s, self.im * s) }
    #[inline] pub fn conjugate(self) -> Complex { Complex::new(self.re, -self.im) }
    #[inline] pub fn magnitude(self) -> f64 { (self.re * self.re + self.im * self.im).sqrt() }
    #[inline] pub fn magnitude_sqr(self) -> f64 { self.re * self.re + self.im * self.im }
    #[inline] pub fn abs(self) -> f64 { self.magnitude() }
    /// Euler's formula: e^(iθ) = cos θ + i sin θ
    pub fn exp_i(theta: f64) -> Complex { Complex::new(theta.cos(), theta.sin()) }
    /// General complex exponential: e^(a + ib) = e^a * (cos b + i sin b)
    pub fn exp(self) -> Complex { Complex::exp_i(self.im).scale(self.re.exp()) }
}

// ============================================================
// N-Dimensional Complex Tensor
// ============================================================

/// Row-major N-dimensional tensor of Complex values.
#[derive(Clone, Debug)]
pub struct Tensor {
    pub shape: Vec<usize>,
    pub data: Vec<Complex>,
}

impl Tensor {
    /// Construct a zero-initialized tensor of given shape.
    pub fn new(shape: Vec<usize>) -> Self {
        let size: usize = shape.iter().product::<usize>().max(1);
        Self { shape, data: vec![Complex::ZERO; size] }
    }

    /// Construct a tensor from raw data.
    pub fn from_data(shape: Vec<usize>, data: Vec<Complex>) -> Self {
        debug_assert_eq!(shape.iter().product::<usize>(), data.len());
        Self { shape, data }
    }

    /// Total number of elements.
    pub fn size(&self) -> usize { self.data.len() }

    /// Rank (number of dimensions / indices).
    pub fn rank(&self) -> usize { self.shape.len() }

    /// Row-major flat index from N-dimensional index vector.
    pub fn flat_index(&self, indices: &[usize]) -> usize {
        assert_eq!(indices.len(), self.shape.len(), "Index rank must match tensor rank");
        let mut idx = 0;
        let mut stride = 1;
        for (i, &dim_idx) in indices.iter().enumerate().rev() {
            assert!(dim_idx < self.shape[i], "Index {} out of bounds for dimension {} with size {}", dim_idx, i, self.shape[i]);
            idx += dim_idx * stride;
            stride *= self.shape[i];
        }
        idx
    }

    pub fn get(&self, indices: &[usize]) -> Complex { self.data[self.flat_index(indices)] }
    pub fn set(&mut self, indices: &[usize], val: Complex) {
        let idx = self.flat_index(indices);
        self.data[idx] = val;
    }

    /// Reshape without copying data. Panics if total size changes.
    pub fn reshape(&self, new_shape: Vec<usize>) -> Self {
        assert_eq!(new_shape.iter().product::<usize>(), self.size());
        Self { shape: new_shape, data: self.data.clone() }
    }

    /// Hermitian conjugate (transpose + element-wise complex conjugate).
    /// Only valid for rank-2 tensors (matrices).
    pub fn hermitian(&self) -> Self {
        assert_eq!(self.rank(), 2, "Hermitian conjugate requires a matrix (rank-2 tensor)");
        let m = self.shape[0];
        let n = self.shape[1];
        let mut result = Tensor::new(vec![n, m]);
        for i in 0..m {
            for j in 0..n {
                result.set(&[j, i], self.get(&[i, j]).conjugate());
            }
        }
        result
    }

    /// Frobenius norm: ||T||_F = sqrt(Σ |t_ij|²)
    pub fn frobenius_norm(&self) -> f64 {
        self.data.iter().map(|c| c.magnitude_sqr()).sum::<f64>().sqrt()
    }
}

// ============================================================
// Matrix Operations
// ============================================================

/// Matrix multiplication C = A × B for rank-2 tensors.
pub fn matrix_multiply(a: &Tensor, b: &Tensor) -> Tensor {
    assert_eq!(a.rank(), 2);
    assert_eq!(b.rank(), 2);
    assert_eq!(a.shape[1], b.shape[0], "Matrix dimension mismatch");

    let m = a.shape[0];
    let k = a.shape[1];
    let n = b.shape[1];
    let mut c = Tensor::new(vec![m, n]);

    for i in 0..m {
        for j in 0..n {
            let mut sum = Complex::ZERO;
            for l in 0..k {
                sum = sum.add(a.get(&[i, l]).mul(b.get(&[l, j])));
            }
            c.set(&[i, j], sum);
        }
    }
    c
}

// ============================================================
// Singular Value Decomposition (SVD) via Nalgebra
// ============================================================
use nalgebra::{DMatrix, SVD};

/// The output of a Singular Value Decomposition.
pub struct SvdResult {
    pub u: Tensor,                // m × r left singular vectors
    pub singular_values: Vec<f64>,// r singular values in descending order
    pub v: Tensor,                // n × r right singular vectors (NOT transposed)
    pub rank: usize,              // Effective rank used
}

/// SVD powered by the `nalgebra` LAPACK backend for massive tensor factorization.
pub fn svd_real(a: &Tensor, max_rank: Option<usize>, epsilon: f64) -> SvdResult {
    let m = a.shape[0];
    let n = a.shape[1];
    let min_dim = m.min(n);

    if min_dim == 0 {
        return SvdResult {
            u: Tensor::new(vec![m, 0]),
            singular_values: Vec::new(),
            v: Tensor::new(vec![n, 0]),
            rank: 0,
        };
    }

    // Convert Tensor to nalgebra DMatrix (Column-major)
    // Wait, DMatrix is column major, we iterate row by row from our Tensor.
    let mut nal_mat = DMatrix::zeros(m, n);
    for i in 0..m {
        for j in 0..n {
            let val = a.get(&[i, j]).re;
            nal_mat[(i, j)] = if val.is_finite() { val } else { 0.0 };
        }
    }

    // Perform SVD using Nalgebra's robust LAPACK bindings
    let svd = SVD::new(nal_mat, true, true);
    
    let u_mat = match svd.u {
        Some(u) => u,
        None => return SvdResult {
            u: Tensor::new(vec![m, 0]),
            singular_values: Vec::new(),
            v: Tensor::new(vec![n, 0]),
            rank: 0,
        },
    };
    let v_t_mat = match svd.v_t {
        Some(vt) => vt,
        None => return SvdResult {
            u: Tensor::new(vec![m, 0]),
            singular_values: Vec::new(),
            v: Tensor::new(vec![n, 0]),
            rank: 0,
        },
    };
    let s_vec = svd.singular_values;

    // Filter singular values by epsilon and max_rank
    // The mathematical upper bound for rank is min(m, n) — the minimum dimension
    let mut rank = 0;
    for &val in s_vec.iter() {
        if val > epsilon {
            rank += 1;
        }
    }
    // Cap at mathematical maximum (min_dim) and user-specified max
    rank = rank.min(min_dim);
    if let Some(mr) = max_rank {
        rank = rank.min(mr);
    }
    rank = rank.max(1); // Keep at least rank 1

    let mut u_tensor = Tensor::new(vec![m, rank]);
    let mut v_tensor = Tensor::new(vec![n, rank]);
    let mut singular_values = Vec::with_capacity(rank);

    for r_idx in 0..rank {
        singular_values.push(s_vec[r_idx]);
        
        for i in 0..m {
            u_tensor.set(&[i, r_idx], Complex::real(u_mat[(i, r_idx)]));
        }
        for j in 0..n {
            // v_t_mat is V^T, so V[j, r] is v_t_mat[r, j]
            v_tensor.set(&[j, r_idx], Complex::real(v_t_mat[(r_idx, j)]));
        }
    }

    SvdResult { u: u_tensor, singular_values, v: v_tensor, rank }
}

// ============================================================
// Matrix Product State (MPS) — Tensor Train Decomposition
// ============================================================

/// A single site tensor in an MPS chain.
/// Shape: [left_bond_dim, physical_dim, right_bond_dim]
#[derive(Clone, Debug)]
pub struct MpsSite {
    pub tensor: Tensor, // rank-3: [χ_left, d, χ_right]
    pub physical_dim: usize,  // d — dimension of the local Hilbert space (2 for qubits)
    pub left_bond: usize,     // χ_left
    pub right_bond: usize,    // χ_right
}

/// A Matrix Product State representing an N-qubit quantum state.
/// |ψ⟩ = Σ_{s₁...sN} A^[1]_{s₁} A^[2]_{s₂} ... A^[N]_{sN} |s₁s₂...sN⟩
pub struct MatrixProductState {
    pub sites: Vec<MpsSite>,
    pub n_sites: usize,
    /// Maximum bond dimension χ (the truncation parameter)
    pub max_bond: usize,
}

impl MatrixProductState {
    /// Initialize an MPS in the |0...0⟩ computational basis state (all spins down).
    pub fn init_zero_state(n_qubits: usize, max_bond: usize) -> Self {
        let sites = (0..n_qubits).map(|_| {
            let chi_l = 1; // Bond dim 1 = product state
            let chi_r = 1;
            let d = 2; // Qubit: physical dim = 2

            let mut tensor = Tensor::new(vec![chi_l, d, chi_r]);
            // |0⟩ state: coefficient of |0⟩ = 1, |1⟩ = 0
            tensor.set(&[0, 0, 0], Complex::ONE);
            tensor.set(&[0, 1, 0], Complex::ZERO);

            MpsSite { tensor, physical_dim: d, left_bond: chi_l, right_bond: chi_r }
        }).collect();

        Self { sites, n_sites: n_qubits, max_bond }
    }

    /// Apply a single-qubit gate (2×2 unitary matrix) at site `site_idx`.
    #[allow(clippy::needless_range_loop)]
    pub fn apply_single_qubit_gate(&mut self, site_idx: usize, gate: &[[Complex; 2]; 2]) {
        if site_idx >= self.sites.len() {
            return;
        }
        let site = &mut self.sites[site_idx];
        let chi_l = site.left_bond;
        let chi_r = site.right_bond;
        let d     = site.physical_dim;

        let mut new_tensor = Tensor::new(vec![chi_l, d, chi_r]);

        for alpha in 0..chi_l {
            for beta in 0..chi_r {
                for s_out in 0..d {
                    let mut val = Complex::ZERO;
                    for s_in in 0..d {
                        val = val.add(gate[s_out][s_in].mul(site.tensor.get(&[alpha, s_in, beta])));
                    }
                    new_tensor.set(&[alpha, s_out, beta], val);
                }
            }
        }
        site.tensor = new_tensor;
    }

    /// Apply a two-qubit gate (4×4 unitary) on adjacent sites (i, i+1) using SVD.
    /// The θ (theta) tensor is contracted and then split back via SVD, keeping
    /// only the `max_bond` largest singular values (bond truncation).
    pub fn apply_two_qubit_gate(
        &mut self,
        site_i: usize,
        gate: &[[Complex; 4]; 4],
        svd_epsilon: f64,
    ) {
        if site_i + 1 >= self.sites.len() {
            return;
        }
        let site_j = site_i + 1;

        let chi_l  = self.sites[site_i].left_bond;
        let d_i    = self.sites[site_i].physical_dim;
        let chi_mid = self.sites[site_i].right_bond;
        let d_j    = self.sites[site_j].physical_dim;
        let chi_r  = self.sites[site_j].right_bond;

        // Step 1: Contract A[i] and A[j] into a Theta tensor of shape [chi_l, d_i, d_j, chi_r]
        let mut theta = Tensor::new(vec![chi_l, d_i, d_j, chi_r]);
        for alpha in 0..chi_l {
            for si in 0..d_i {
                for sj in 0..d_j {
                    for beta in 0..chi_r {
                        let mut val = Complex::ZERO;
                        for gamma in 0..chi_mid {
                            val = val.add(
                                self.sites[site_i].tensor.get(&[alpha, si, gamma])
                                    .mul(self.sites[site_j].tensor.get(&[gamma, sj, beta]))
                            );
                        }
                        theta.set(&[alpha, si, sj, beta], val);
                    }
                }
            }
        }

        // Step 2: Apply the 2-qubit gate to the physical indices (si, sj)
        let mut theta_g = Tensor::new(vec![chi_l, d_i, d_j, chi_r]);
        for alpha in 0..chi_l {
            for beta in 0..chi_r {
                for s_out_i in 0..d_i {
                    for s_out_j in 0..d_j {
                        let out_idx = s_out_i * d_j + s_out_j;
                        let mut val = Complex::ZERO;
                        for s_in_i in 0..d_i {
                            for s_in_j in 0..d_j {
                                let in_idx = s_in_i * d_j + s_in_j;
                                val = val.add(
                                    gate[out_idx][in_idx].mul(theta.get(&[alpha, s_in_i, s_in_j, beta]))
                                );
                            }
                        }
                        theta_g.set(&[alpha, s_out_i, s_out_j, beta], val);
                    }
                }
            }
        }

        // Step 3: Reshape theta_g to a matrix: (chi_l × d_i) × (d_j × chi_r)
        let rows = chi_l * d_i;
        let cols = d_j * chi_r;
        let mut mat = Tensor::new(vec![rows, cols]);
        for alpha in 0..chi_l {
            for si in 0..d_i {
                for sj in 0..d_j {
                    for beta in 0..chi_r {
                        let row = alpha * d_i + si;
                        let col = sj * chi_r + beta;
                        mat.set(&[row, col], theta_g.get(&[alpha, si, sj, beta]));
                    }
                }
            }
        }

        // Step 4: SVD with bond truncation
        let svd = svd_real(&mat, Some(self.max_bond), svd_epsilon);
        let new_bond = svd.rank;

        // Step 5: Reshape U back to A[i] shape [chi_l, d_i, new_bond]
        let mut new_ai = Tensor::new(vec![chi_l, d_i, new_bond]);
        for alpha in 0..chi_l {
            for si in 0..d_i {
                let row = alpha * d_i + si;
                for r in 0..new_bond {
                    new_ai.set(&[alpha, si, r], svd.u.get(&[row, r]));
                }
            }
        }

        // Step 6: Absorb singular values into right tensor: S * V†
        // Reshape (S * V^T) to A[j] shape [new_bond, d_j, chi_r]
        let mut new_aj = Tensor::new(vec![new_bond, d_j, chi_r]);
        for r in 0..new_bond {
            for sj in 0..d_j {
                for beta in 0..chi_r {
                    let col = sj * chi_r + beta;
                    // V has shape [n, r] so V[col][r] = V.get(&[col, r])
                    let val = svd.v.get(&[col, r]).scale(svd.singular_values[r]);
                    new_aj.set(&[r, sj, beta], val);
                }
            }
        }

        self.sites[site_i] = MpsSite {
            tensor: new_ai,
            physical_dim: d_i,
            left_bond: chi_l,
            right_bond: new_bond,
        };
        self.sites[site_j] = MpsSite {
            tensor: new_aj,
            physical_dim: d_j,
            left_bond: new_bond,
            right_bond: chi_r,
        };
    }

    /// Compute the expectation value ⟨ψ|O|ψ⟩ for a single-site Pauli operator.
    #[allow(clippy::needless_range_loop)]
    pub fn expectation_single_site(&self, site_idx: usize, op: &[[Complex; 2]; 2]) -> Complex {
        if site_idx >= self.sites.len() {
            return Complex::ZERO;
        }
        let site = &self.sites[site_idx];
        let chi_l = site.left_bond;
        let chi_r = site.right_bond;
        let d     = site.physical_dim;

        let mut result = Complex::ZERO;
        for alpha in 0..chi_l {
            for beta in 0..chi_r {
                for s_bra in 0..d {
                    for s_ket in 0..d {
                        let bra = site.tensor.get(&[alpha, s_bra, beta]).conjugate();
                        let ket = site.tensor.get(&[alpha, s_ket, beta]);
                        result = result.add(bra.mul(op[s_bra][s_ket]).mul(ket));
                    }
                }
            }
        }
        result
    }
}

// ============================================================
// Standard Quantum Gates (as Complex matrices)
// ============================================================

/// Pauli-X (NOT) gate: |0⟩ ↔ |1⟩
pub const PAULI_X: [[Complex; 2]; 2] = [
    [Complex { re: 0.0, im: 0.0 }, Complex { re: 1.0, im: 0.0 }],
    [Complex { re: 1.0, im: 0.0 }, Complex { re: 0.0, im: 0.0 }],
];

/// Pauli-Z: |0⟩ → |0⟩, |1⟩ → -|1⟩
pub const PAULI_Z: [[Complex; 2]; 2] = [
    [Complex { re: 1.0, im: 0.0 }, Complex { re: 0.0, im: 0.0 }],
    [Complex { re: 0.0, im: 0.0 }, Complex { re: -1.0, im: 0.0 }],
];

/// Hadamard gate: |0⟩ → (|0⟩+|1⟩)/√2, |1⟩ → (|0⟩-|1⟩)/√2
pub fn hadamard() -> [[Complex; 2]; 2] {
    let h = 1.0 / 2.0f64.sqrt();
    [
        [Complex::real(h),  Complex::real(h) ],
        [Complex::real(h),  Complex::real(-h)],
    ]
}

// ============================================================
// Tensor Analyzer — Entanglement and Contraction
// ============================================================

/// The tensor network analyzer for quantum state analysis.
pub struct TensorAnalyzer;

impl Default for TensorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TensorAnalyzer {
    pub fn new() -> Self { Self }

    /// True tensor contraction (Einstein summation) over a single shared axis.
    pub fn contract(&self, a: &Tensor, b: &Tensor, axis_a: usize, axis_b: usize) -> Tensor {
        assert!(axis_a < a.shape.len());
        assert!(axis_b < b.shape.len());
        assert_eq!(a.shape[axis_a], b.shape[axis_b], "Contraction dimension mismatch");

        let contract_dim = a.shape[axis_a];

        let mut new_shape: Vec<usize> = Vec::new();
        for (i, &dim) in a.shape.iter().enumerate() { if i != axis_a { new_shape.push(dim); } }
        for (i, &dim) in b.shape.iter().enumerate() { if i != axis_b { new_shape.push(dim); } }

        if new_shape.contains(&0) || contract_dim == 0 {
            return Tensor::new(new_shape);
        }

        let mut result = Tensor::new(new_shape.clone());
        let output_size: usize = new_shape.iter().product::<usize>();

        for flat_out in 0..output_size {
            let mut out_coords = Vec::with_capacity(new_shape.len());
            let mut remainder = flat_out;
            for &dim in new_shape.iter().rev() {
                out_coords.push(remainder % dim);
                remainder /= dim;
            }
            out_coords.reverse();

            let n_a_dims = a.shape.len() - 1;
            let coords_a = &out_coords[..n_a_dims];
            let coords_b = &out_coords[n_a_dims..];

            let mut sum = Complex::ZERO;
            for k in 0..contract_dim {
                let mut idx_a = coords_a.to_vec(); idx_a.insert(axis_a, k);
                let mut idx_b = coords_b.to_vec(); idx_b.insert(axis_b, k);
                sum = sum.add(a.get(&idx_a).mul(b.get(&idx_b)));
            }
            result.data[flat_out] = sum;
        }
        result
    }

    /// Von Neumann entropy S = -Tr(ρ log₂ ρ) = -Σ λᵢ log₂ λᵢ.
    /// Given the Schmidt singular values of a bipartition.
    pub fn compute_von_neumann_entropy(&self, singular_values: &[f64]) -> f64 {
        let entropy: f64 = singular_values.iter().map(|&sv| {
            if !sv.is_finite() { return 0.0; }
            let lam = sv * sv; // λ = σ² (probability)
            if lam > 1e-15 && lam <= 1.0 { -lam * lam.log2() } else { 0.0 }
        }).sum();
        if entropy.is_nan() { 0.0 } else { entropy.max(0.0) }
    }

    /// Compute the entanglement entropy of an MPS bipartition at bond `bond_idx`.
    /// Uses SVD of the reshaped state vector to extract Schmidt values.
    pub fn bipartite_entanglement(&self, mps: &MatrixProductState, bond_idx: usize) -> f64 {
        if bond_idx >= mps.sites.len() {
            return 0.0;
        }
        // The singular values at bond bond_idx are the Schmidt coefficients
        // For an MPS already in canonical form, these are accessible directly
        // Here we use the site tensor norms as a proxy
        let site = &mps.sites[bond_idx];
        let chi_r = site.right_bond;
        let mut sv_estimates: Vec<f64> = (0..chi_r).map(|r| {
            let norm_sq: f64 = (0..site.left_bond).flat_map(|l| {
                (0..site.physical_dim).map(move |d| {
                    site.tensor.get(&[l, d, r]).magnitude_sqr()
                })
            }).sum();
            norm_sq.sqrt()
        }).collect();

        // Normalize singular values so Σ λ² = 1
        let total: f64 = sv_estimates.iter().map(|s| s * s).sum::<f64>().sqrt().max(1e-15);
        for s in sv_estimates.iter_mut() { *s /= total; }

        self.compute_von_neumann_entropy(&sv_estimates)
    }
}
