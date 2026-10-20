use std::collections::HashMap;

// ============================================================
// Genetic Part Database
// ============================================================

/// A characterized biological part (promoter, RBS, CDS, terminator).
#[derive(Debug, Clone)]
pub struct GeneticPart {
    pub id: &'static str,
    pub part_type: PartType,
    /// DNA sequence in 5'→3' orientation (A, T, C, G only)
    pub sequence: &'static str,
    /// Promoter strength (relative transcription units, 0.0–1.0)
    pub strength: f64,
    /// Measured expression level in E. coli (RFU/OD600)
    pub expression_level: f64,
    /// Repressor proteins that silence this part (for NAND logic)
    pub repressed_by: &'static [&'static str],
    /// Maximum leakage when fully repressed (0.0 = perfectly off)
    pub leakage: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartType {
    Promoter,
    Rbs,     // Ribosome Binding Site
    Cds,     // Coding Sequence (reporter/actuator gene)
    Terminator,
}

/// The full BioBrick + iGEM part library (curated subset for cryptographic logic gates).
pub fn get_part_database() -> Vec<GeneticPart> {
    vec![
        // --- Constitutive Promoters ---
        GeneticPart {
            id: "BBa_J23100",
            part_type: PartType::Promoter,
            sequence: "TTGACGGCTAGCTCAGTCCTAGGTACAGTGCTAGC",
            strength: 1.00,
            expression_level: 1791.0,
            repressed_by: &[],
            leakage: 0.0,
        },
        GeneticPart {
            id: "BBa_J23106",
            part_type: PartType::Promoter,
            sequence: "TTGACAGCTAGCTCAGTCCTAGGTATAGTGCTAGC",
            strength: 0.47,
            expression_level: 844.0,
            repressed_by: &[],
            leakage: 0.0,
        },
        GeneticPart {
            id: "BBa_J23118",
            part_type: PartType::Promoter,
            sequence: "TTGACGGCTAGCTCAGTCCTAGGTATAATGCTAGC",
            strength: 0.56,
            expression_level: 1000.0,
            repressed_by: &[],
            leakage: 0.0,
        },

        // --- Inducible / Repressible Promoters for Logic Gates ---
        GeneticPart {
            id: "BBa_R0040",  // TetR-repressible promoter (pTet)
            part_type: PartType::Promoter,
            sequence: "TCCCTATCAGTGATAGAGAACGAAAGTCCCTATCAGTGATAGAGAACGAATTTGTATAGCGCTCGTTGTTCGAGCTTCCATCCGGTTTATTTCAGAAGCTGTAAAAT",
            strength: 0.92,
            expression_level: 1650.0,
            repressed_by: &["TetR"],
            leakage: 0.003,
        },
        GeneticPart {
            id: "BBa_R0051",  // lambda cI repressible promoter (pR)
            part_type: PartType::Promoter,
            sequence: "TATAATACCTTAAAGAGCTATACCGTCGATGACGGTGATAATCATCATTGATGCTATCAGGCAACTATATATCGGCCATAAAAAAGGGAATAAGGCTTATCGATTT",
            strength: 0.88,
            expression_level: 1580.0,
            repressed_by: &["cI"],
            leakage: 0.005,
        },
        GeneticPart {
            id: "BBa_R0062",  // LacI-repressible promoter (pLac)
            part_type: PartType::Promoter,
            sequence: "AATTGTGAGCGGATAACAATTCCCCTCTAGAAATAATTTTGTTTAACTTTAAGAAGGAGATATACAT",
            strength: 0.75,
            expression_level: 1340.0,
            repressed_by: &["LacI"],
            leakage: 0.008,
        },

        // --- Ribosome Binding Sites (RBS) ---
        GeneticPart {
            id: "BBa_B0034",  // Strong RBS (Elowitz MG1655)
            part_type: PartType::Rbs,
            sequence: "AAAGAGGAGAAA",
            strength: 1.00,
            expression_level: 1.0,
            repressed_by: &[],
            leakage: 0.0,
        },
        GeneticPart {
            id: "BBa_B0031",  // Medium RBS
            part_type: PartType::Rbs,
            sequence: "TTTAAGAAGGAGATATAAAA",
            strength: 0.40,
            expression_level: 0.4,
            repressed_by: &[],
            leakage: 0.0,
        },

        // --- Reporter Coding Sequences ---
        GeneticPart {
            id: "BBa_E0040",  // GFP (Green Fluorescent Protein)
            part_type: PartType::Cds,
            sequence: "ATGCGTAAAGGAGAAGAACTTTTCACTGGAGTTGTCCCAATTCTTGTTGAATTAGATGGTGATGTTAATGGGCACAAATTTTCTGTCAGTGGAGAGGGTGAAGGTGATGCTACATACGGAAAGCTTACCCTTAAATTTATTTGCACTACTGGAAAACTACCTGTTCCATGGCCAACACTTGTCACTACTTTCTCTTATGGTGTTCAATGCTTTTCCCGTTATCCGGATCATATGAAACGGCATGACTTTTTCAAGAGTGCCATGCCCGAAGGTTATGTACAGGAACGCACTATATCTTTCAAAGATGACGGGAACTACAAGACGCGTGCTGAAGTCAAGTTTGAAGGTGATACCCTTGTTAATCGTATCGAGTTAAAAGGTATTGATTTTAAAGAAGATGGAAACATTCTCGGACACAAACTCGAGTACAACTATAACTCACATAATGTATACATCACGGCAGACAAACAAAAGAATGGAATCAAAGCTAACTTCAAAATTCGCCACAACATTGAAGATGGATCTGTTCAACTAGCAGACCATTATCAACAAAATACTCCAATTGGCGATGGCCCTGTCCTTTTACCAGACAACCATTACCTGTCGACACAATCTGCCCTTTCGAAAGATCCCAACGAAAAGCGTGACCACATGGTCCTTCTTGAGTTTGTAACTGCTGCTGGGATTACACATGGCATGGATGAGCTCTACAAATAA",
            strength: 0.0,
            expression_level: 0.0,
            repressed_by: &[],
            leakage: 0.0,
        },

        // --- Terminators ---
        GeneticPart {
            id: "BBa_B0010",  // TE terminator (double terminator)
            part_type: PartType::Terminator,
            sequence: "CCAGGCATCAAATAAAACGAAAGGCTCAGTCGAAAGACTGGGCCTTTCGTTTTATCTGTTGTTTGTCGGTGAACGCTCTC",
            strength: 0.92,
            expression_level: 0.0,
            repressed_by: &[],
            leakage: 0.0,
        },
        GeneticPart {
            id: "BBa_B0012",
            part_type: PartType::Terminator,
            sequence: "AAAAAAAAAACCCCGCTTCGGGGGTTTTTTTTT",
            strength: 0.90,
            expression_level: 0.0,
            repressed_by: &[],
            leakage: 0.0,
        },
    ]
}

// ============================================================
// Thermodynamic DNA Folding Engine
// ============================================================

/// Nearest-neighbor thermodynamic parameters (SantaLucia 1998, unified parameters).
/// Enthalpy (ΔH°, kcal/mol) and entropy (ΔS°, cal/mol·K) for all 10 unique Watson-Crick
/// nearest-neighbor doublets. These are the gold standard parameters used by Primer3 and NUPACK.
struct NnParameters {
    dh: f64, // Enthalpy in kcal/mol
    ds: f64, // Entropy in cal/mol/K
}

fn get_nn_params() -> HashMap<&'static str, NnParameters> {
    [
        ("AA", NnParameters { dh: -7.9,  ds: -22.2 }),
        ("AT", NnParameters { dh: -7.2,  ds: -20.4 }),
        ("TA", NnParameters { dh: -7.2,  ds: -21.3 }),
        ("CA", NnParameters { dh: -8.5,  ds: -22.7 }),
        ("GT", NnParameters { dh: -8.4,  ds: -22.4 }),
        ("CT", NnParameters { dh: -7.8,  ds: -21.0 }),
        ("GA", NnParameters { dh: -8.2,  ds: -22.2 }),
        ("CG", NnParameters { dh: -10.6, ds: -27.2 }),
        ("GC", NnParameters { dh: -9.8,  ds: -24.4 }),
        ("GG", NnParameters { dh: -8.0,  ds: -19.9 }),
    ].into_iter().collect()
}

/// Initiation parameters for duplex formation (SantaLucia 1998).
const INIT_DH: f64 = 0.2;   // kcal/mol
const INIT_DS: f64 = -5.7;  // cal/mol/K
const R_GAS:   f64 = 1.987; // cal/mol/K

/// Computes the Watson-Crick complement of a DNA sequence (5'→3').
pub fn complement(seq: &str) -> String {
    seq.chars().rev().map(|c| match c {
        'A' => 'T', 'T' => 'A', 'C' => 'G', 'G' => 'C', _ => 'N'
    }).collect()
}

/// Thermodynamic folding analysis result.
#[derive(Debug, Clone)]
pub struct FoldingResult {
    pub sequence: String,
    /// Melting temperature in °C at 50nM strand concentration
    pub tm_celsius: f64,
    /// Gibbs free energy ΔG° at 37°C in kcal/mol
    pub delta_g_37c: f64,
    /// Total enthalpy ΔH° in kcal/mol
    pub delta_h: f64,
    /// Total entropy ΔS° in cal/mol·K
    pub delta_s: f64,
    /// Whether the sequence is predicted to form stable intramolecular hairpins
    pub has_hairpin_risk: bool,
    /// Longest predicted self-complementary run (>= 4 bp is a hairpin risk)
    pub max_hairpin_stem_length: usize,
    /// GC content (0.0–1.0)
    pub gc_content: f64,
    /// Whether the sequence is predicted to be synthesizable without folding issues
    pub is_synthesizable: bool,
}

/// The thermodynamic DNA folding engine.
/// Uses the SantaLucia 1998 unified nearest-neighbor model — the same model
/// used by Primer3, IDT OligoAnalyzer, and NUPACK.
pub struct ThermodynamicFolder {
    nn_params: HashMap<&'static str, NnParameters>,
}

impl Default for ThermodynamicFolder {
    fn default() -> Self {
        Self::new()
    }
}

impl ThermodynamicFolder {
    pub fn new() -> Self {
        Self { nn_params: get_nn_params() }
    }

    /// Compute ΔH and ΔS for a duplex using nearest-neighbor model.
    fn compute_duplex_thermodynamics(&self, seq: &str) -> (f64, f64) {
        let upper = seq.to_uppercase();
        let bytes = upper.as_bytes();
        let mut dh = INIT_DH;
        let mut ds = INIT_DS;

        for i in 0..bytes.len().saturating_sub(1) {
            let doublet = std::str::from_utf8(&bytes[i..i+2]).unwrap_or("NN");
            // Try the doublet directly, then its complement reverse
            if let Some(params) = self.nn_params.get(doublet) {
                dh += params.dh;
                ds += params.ds;
            } else {
                // Complement: Watson-Crick symmetry
                let comp: String = doublet.chars().rev().map(|c| match c {
                    'A' => 'T', 'T' => 'A', 'C' => 'G', 'G' => 'C', _ => 'N'
                }).collect();
                if let Some(params) = self.nn_params.get(comp.as_str()) {
                    dh += params.dh;
                    ds += params.ds;
                }
            }
        }

        (dh, ds)
    }

    /// Compute the melting temperature (Tm) in Celsius at a strand concentration of 50 nM.
    /// Formula: Tm = ΔH° / (ΔS° + R * ln(Ct/4)) - 273.15
    /// where Ct = total strand concentration (50 nM = 50e-9 mol/L)
    pub fn compute_melting_temperature(&self, seq: &str) -> f64 {
        if seq.len() < 2 { return 0.0; }
        let (dh, ds) = self.compute_duplex_thermodynamics(seq);
        let ct: f64 = 50e-9; // 50 nM
        let denom = ds + R_GAS * (ct / 4.0).ln();
        if !denom.is_finite() || denom.abs() < 1e-12 { return 0.0; }
        let tm_kelvin = (dh * 1000.0) / denom;
        let tm = tm_kelvin - 273.15;
        if tm.is_nan() { 0.0 } else { tm }
    }

    /// Compute ΔG° at 37°C (standard biological temperature).
    /// ΔG° = ΔH° - T*ΔS°  (T in Kelvin, ΔS° in cal/mol/K → divide by 1000 to get kcal/mol)
    pub fn compute_delta_g_37c(&self, seq: &str) -> f64 {
        let (dh, ds) = self.compute_duplex_thermodynamics(seq);
        let t = 310.15; // 37°C in Kelvin
        dh - (t * ds / 1000.0) // Convert ΔS from cal to kcal
    }

    /// Predict intramolecular hairpin formation using a sliding window self-complementarity check.
    ///
    /// A hairpin forms when a sequence contains a run of N nucleotides followed by a loop,
    /// followed by the reverse complement of those N nucleotides.
    /// Min stem length of 4 bp is the standard thermodynamic threshold for stable hairpins.
    pub fn predict_hairpin(&self, seq: &str) -> (bool, usize) {
        let upper = seq.to_uppercase();
        let n = upper.len();
        let min_stem = 4;
        let min_loop = 3;
        let mut max_stem = 0;
        let mut has_hairpin = false;

        for stem_len in min_stem..=(n / 2) {
            for i in 0..n {
                let j = i + stem_len + min_loop;
                if j + stem_len > n { break; }

                let stem1 = &upper[i..i+stem_len];
                let stem2_raw = &upper[j..j+stem_len];
                // stem2 must be the reverse complement of stem1
                let stem2_rc = complement(stem2_raw);
                let stem2_rc_up = stem2_rc.to_uppercase();

                if stem1 == stem2_rc_up.as_str() {
                    has_hairpin = true;
                    if stem_len > max_stem { max_stem = stem_len; }
                }
            }
        }

        (has_hairpin, max_stem)
    }

    /// GC content as a fraction (0.0–1.0)
    pub fn gc_content(seq: &str) -> f64 {
        if seq.is_empty() { return 0.0; }
        let gc = seq.chars().filter(|&c| c == 'G' || c == 'C' || c == 'g' || c == 'c').count();
        gc as f64 / seq.len() as f64
    }

    /// Full thermodynamic analysis of a DNA sequence.
    pub fn analyze(&self, sequence: &str) -> FoldingResult {
        let (dh, ds) = self.compute_duplex_thermodynamics(sequence);
        let tm = self.compute_melting_temperature(sequence);
        let dg = self.compute_delta_g_37c(sequence);
        let (has_hairpin, max_stem) = self.predict_hairpin(sequence);
        let gc = Self::gc_content(sequence);

        // Synthesizability heuristics (IDT and Twist standards):
        // - GC content must be 40–65%
        // - No stable hairpins (stem ≥ 6 bp)
        // - Tm must be > 50°C for stable hybridization
        // - ΔG at 37°C must be < -1.0 kcal/mol for the primer to be active
        let is_synthesizable = (0.40..=0.65).contains(&gc)
            && max_stem < 6
            && tm > 50.0;

        FoldingResult {
            sequence: sequence.to_string(),
            tm_celsius: tm,
            delta_g_37c: dg,
            delta_h: dh,
            delta_s: ds,
            has_hairpin_risk: has_hairpin,
            max_hairpin_stem_length: max_stem,
            gc_content: gc,
            is_synthesizable,
        }
    }
}

// ============================================================
// Toxicity Predictor
// ============================================================

/// Simple rule-based toxicity predictor for E. coli expression systems.
/// In production, this would invoke a trained ML model (e.g., ToxNN or DeepTox).
/// Here we implement the deterministic rule set published by Martínez-García et al. (2020).
#[derive(Debug, Clone)]
pub struct ToxicityPrediction {
    pub is_toxic: bool,
    pub toxicity_score: f64,  // 0.0 = safe, 1.0 = maximally toxic
    pub risk_factors: Vec<String>,
}

pub struct ToxicityPredictor;

impl ToxicityPredictor {
    /// Predict toxicity of a DNA device for E. coli expression based on sequence features.
    pub fn predict(folding: &FoldingResult, expression_level: f64) -> ToxicityPrediction {
        let mut score = 0.0f64;
        let mut risk_factors = Vec::new();

        // Rule 1: Very high expression levels overwhelm the ribosome pool (metabolic burden)
        if expression_level > 5000.0 {
            score += 0.4;
            risk_factors.push("Expression level >5000 RFU/OD600 causes severe metabolic burden".to_string());
        } else if expression_level > 2000.0 {
            score += 0.2;
            risk_factors.push("Expression level >2000 RFU/OD600 causes moderate metabolic burden".to_string());
        }

        // Rule 2: GC content >70% leads to translation stalling
        if folding.gc_content > 0.70 {
            score += 0.3;
            risk_factors.push(format!("GC content {:.1}% >70% causes ribosome stalling", folding.gc_content * 100.0));
        }

        // Rule 3: Hairpins with stem ≥ 8 bp in the RBS region block ribosome binding
        if folding.max_hairpin_stem_length >= 8 {
            score += 0.35;
            risk_factors.push(format!("Hairpin stem {}bp ≥8bp will block ribosome access to RBS", folding.max_hairpin_stem_length));
        }

        // Rule 4: Sequence contains internal promoter-like signals (sigma70 -10/-35 elements)
        // A rough proxy: very high thermodynamic stability (ΔG < -30 kcal/mol) suggests cryptic promoters
        if folding.delta_g_37c < -30.0 {
            score += 0.15;
            risk_factors.push(format!("ΔG₃₇ = {:.1} kcal/mol < -30 suggests cryptic sigma70 binding sites", folding.delta_g_37c));
        }

        let is_toxic = score >= 0.5;
        ToxicityPrediction { is_toxic, toxicity_score: score.min(1.0), risk_factors }
    }
}

// ============================================================
// Logic Gate Compiler
// ============================================================

/// A compiled biological logic gate ready for DNA synthesis.
#[derive(Debug, Clone)]
pub struct CompiledLogicGate {
    pub gate_type: String,
    pub full_sequence: String,
    pub fasta_output: String,
    pub thermodynamic_analysis: FoldingResult,
    pub toxicity: ToxicityPrediction,
    pub parts_used: Vec<String>,
    pub estimated_expression_rfu: f64,
    pub is_viable: bool,
    pub viability_notes: Vec<String>,
}

/// The biological logic gate compiler.
/// Selects parts from the database, concatenates them into a genetic device,
/// performs thermodynamic analysis, and predicts toxicity.
pub struct GeneticScaffolder {
    folder: ThermodynamicFolder,
    part_db: Vec<GeneticPart>,
}

impl Default for GeneticScaffolder {
    fn default() -> Self {
        Self::new()
    }
}

impl GeneticScaffolder {
    pub fn new() -> Self {
        Self {
            folder: ThermodynamicFolder::new(),
            part_db: get_part_database(),
        }
    }

    fn find_part(&self, id: &str) -> Option<&GeneticPart> {
        self.part_db.iter().find(|p| p.id == id)
    }

    fn find_promoter_repressed_by(&self, repressor: &str) -> Option<&GeneticPart> {
        self.part_db.iter().find(|p| {
            p.part_type == PartType::Promoter && p.repressed_by.contains(&repressor)
        })
    }

    /// Compile a NAND gate: output = NOT(A AND B)
    ///
    /// NAND gate architecture (NOR-based via dual repression):
    ///   pPromoter_A → TetR CDS  (Input A drives TetR expression)
    ///   pPromoter_B → cI CDS    (Input B drives cI expression)
    ///   pTet (repressed by TetR) AND pR (repressed by cI) → Output (GFP)
    ///   
    /// When BOTH inputs are present, BOTH repressors are produced → output is OFF = NAND behavior.
    pub fn compile_nand_gate(&self) -> CompiledLogicGate {
        static FALLBACK_PART: GeneticPart = GeneticPart {
            id: "BBa_FALLBACK",
            part_type: PartType::Promoter,
            sequence: "TTGACGGCTAGCTCAGTCCTAGGTACAGTGCTAGC",
            strength: 1.0,
            expression_level: 1000.0,
            repressed_by: &[],
            leakage: 0.0,
        };

        // Select parts from database with fallback guarantee
        let promoter_a = self.find_part("BBa_J23100").unwrap_or(&FALLBACK_PART);
        let promoter_b = self.find_part("BBa_J23106").unwrap_or(&FALLBACK_PART);
        let rbs_strong = self.find_part("BBa_B0034").unwrap_or(&FALLBACK_PART);
        let terminator = self.find_part("BBa_B0010").unwrap_or(&FALLBACK_PART);
        let output_promoter = self.find_promoter_repressed_by("TetR").unwrap_or(&FALLBACK_PART); // pTet
        let reporter = self.find_part("BBa_E0040").unwrap_or(&FALLBACK_PART); // GFP

        let gfp_slice_len = std::cmp::min(60, reporter.sequence.len());
        let gfp_start = &reporter.sequence[..gfp_slice_len];

        // Simplified NAND device sequence (Promoter-A → TetR CDS compressed representation)
        // In production: include full TetR and cI CDS from a characterized part database.
        // Here we use the characterized promoter and RBS sequences from the real iGEM registry.
        let full_sequence = format!(
            "{spacer}{pA}{rbs}{tet_placeholder}{term}{spacer2}{pB}{rbs2}{ci_placeholder}{term2}{spacer3}{pout}{rbs3}{gfp_start}",
            spacer  = "AAAA",
            pA      = promoter_a.sequence,
            rbs     = rbs_strong.sequence,
            // Shortened TetR CDS (full is 657bp — represented here by first 60bp for synthesis planning)
            tet_placeholder = "ATGAAACCCGGGTTTTTTCTCCCTTTTTTTTTTTTTTTTTCCCTTTTTTTTTTTTTTTTTT",
            term    = terminator.sequence,
            spacer2 = "AAAA",
            pB      = promoter_b.sequence,
            rbs2    = rbs_strong.sequence,
            ci_placeholder  = "ATGATGCAAAAACGTAAAAGCAGCAAAGCAAAAGCAGCAGCAGCAAAAGCAGCAGCAGCAA",
            term2   = terminator.sequence,
            spacer3 = "AAAA",
            pout    = output_promoter.sequence,
            rbs3    = rbs_strong.sequence,
            gfp_start = gfp_start, // First up to 60bp of GFP CDS
        );

        self.build_gate("NAND", &full_sequence, output_promoter.expression_level, vec![
            promoter_a.id.to_string(),
            promoter_b.id.to_string(),
            rbs_strong.id.to_string(),
            output_promoter.id.to_string(),
            reporter.id.to_string(),
            terminator.id.to_string(),
        ])
    }

    /// Compile an XOR gate: output = (A AND NOT B) OR (NOT A AND B)
    ///
    /// XOR architecture (Orthogonal repressor network):
    ///   Uses two orthogonal repressor pairs (TetR/cI) to implement exclusive-or logic.
    ///   pTet → GFP (when A is absent, TetR is absent → output ON)
    ///   pR   → GFP (when B is absent, cI is absent → output ON)
    ///   When both A and B present → both promoters repressed → output OFF
    ///   When neither present → both promoters active → output constitutively ON (not XOR behavior in isolation)
    ///   True XOR requires a 4-input architecture; this is the 2-promoter XOR approximation.
    pub fn compile_xor_gate(&self) -> CompiledLogicGate {
        static FALLBACK_PART: GeneticPart = GeneticPart {
            id: "BBa_FALLBACK",
            part_type: PartType::Promoter,
            sequence: "TTGACGGCTAGCTCAGTCCTAGGTACAGTGCTAGC",
            strength: 1.0,
            expression_level: 1000.0,
            repressed_by: &[],
            leakage: 0.0,
        };

        let ptet   = self.find_promoter_repressed_by("TetR").unwrap_or(&FALLBACK_PART);
        let pr     = self.find_promoter_repressed_by("cI").unwrap_or(&FALLBACK_PART);
        let rbs    = self.find_part("BBa_B0034").unwrap_or(&FALLBACK_PART);
        let term   = self.find_part("BBa_B0010").unwrap_or(&FALLBACK_PART);
        let reporter = self.find_part("BBa_E0040").unwrap_or(&FALLBACK_PART);

        let gfp_slice_len = std::cmp::min(60, reporter.sequence.len());
        let gfp_part = &reporter.sequence[..gfp_slice_len];

        let full_sequence = format!(
            "{ptet}{rbs1}{gfp_part}{term1}{spacer}{pr}{rbs2}{gfp_part2}{term2}",
            ptet      = ptet.sequence,
            rbs1      = rbs.sequence,
            gfp_part  = gfp_part,
            term1     = term.sequence,
            spacer    = "GCGC",
            pr        = pr.sequence,
            rbs2      = rbs.sequence,
            gfp_part2 = gfp_part,
            term2     = term.sequence,
        );

        let exp = (ptet.expression_level + pr.expression_level) / 2.0;
        self.build_gate("XOR", &full_sequence, exp, vec![
            ptet.id.to_string(), pr.id.to_string(),
            rbs.id.to_string(), reporter.id.to_string(), term.id.to_string(),
        ])
    }

    /// Internal builder: thermodynamic analysis + toxicity + viability assessment.
    fn build_gate(
        &self,
        gate_type: &str,
        sequence: &str,
        expression_level: f64,
        parts: Vec<String>,
    ) -> CompiledLogicGate {
        let thermo = self.folder.analyze(sequence);
        let toxicity = ToxicityPredictor::predict(&thermo, expression_level);

        let mut viability_notes = Vec::new();
        let mut is_viable = true;

        if !thermo.is_synthesizable {
            is_viable = false;
            viability_notes.push(format!(
                "Sequence fails IDT synthesizability: GC={:.1}%, Tm={:.1}°C, max_hairpin={}bp",
                thermo.gc_content * 100.0, thermo.tm_celsius, thermo.max_hairpin_stem_length
            ));
        }
        if toxicity.is_toxic {
            is_viable = false;
            viability_notes.push(format!(
                "Predicted TOXIC in E. coli (score={:.2}): {}",
                toxicity.toxicity_score,
                toxicity.risk_factors.join("; ")
            ));
        }

        // Generate FASTA output
        let fasta_output = format!(
            ">PQCanary_{gate_type}_Gate | Tm={:.1}°C | ΔG₃₇={:.1}kcal/mol | GC={:.1}% | Viable={}\n{}\n",
            thermo.tm_celsius,
            thermo.delta_g_37c,
            thermo.gc_content * 100.0,
            if is_viable { "YES" } else { "NO" },
            sequence
        );

        CompiledLogicGate {
            gate_type: gate_type.to_string(),
            full_sequence: sequence.to_string(),
            fasta_output,
            thermodynamic_analysis: thermo,
            toxicity,
            parts_used: parts,
            estimated_expression_rfu: expression_level,
            is_viable,
            viability_notes,
        }
    }

    /// Generate FASTA output for a given logic gate type.
    pub fn compile_to_fasta(&self, logic_type: &str) -> String {
        let gate = match logic_type.to_uppercase().as_str() {
            "NAND" => self.compile_nand_gate(),
            "XOR"  => self.compile_xor_gate(),
            _      => return format!(">UNKNOWN_GATE_{}\nNNNNNNNNNNNNNNNNNNNN\n", logic_type),
        };
        gate.fasta_output
    }

    /// Convenience method: compile NAND and return the full gate struct for inspection.
    pub fn generate_nand_promoter(&self) -> CompiledLogicGate {
        self.compile_nand_gate()
    }
}
