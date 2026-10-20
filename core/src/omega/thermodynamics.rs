use std::f64::consts::LN_2;

/// A simple summary report from the `simulate_landauer_limit` convenience method.
/// This is the return type that the Tauri commands and REST API handlers reference.
#[derive(Debug, Clone)]
pub struct LandauerReport {
    /// The temperature at which the simulation was run (Kelvin).
    pub temperature_kelvin: f64,
    /// The Landauer minimum energy cost per bit erasure at this temperature (Joules).
    pub landauer_limit_joules: f64,
    /// Total minimum heat dissipation for the simulated circuit (Joules).
    pub total_dissipation_joules: f64,
    /// Total dissipation in femtojoules (fJ) — more practical for chip-level analysis.
    pub total_dissipation_femtojoules: f64,
    /// Fraction of gates that are irreversible (0.0 = fully reversible, 1.0 = all irreversible).
    pub irreversible_fraction: f64,
    /// True if the thermal dissipation exceeds the threshold where a thermal SCA is practical.
    /// Threshold: total_dissipation > 1e-15 J (1 femtojoule) — detectable by IR cameras.
    pub thermal_side_channel_risk: bool,
}

// ============================================================
// Physical Constants
// ============================================================

/// Boltzmann constant in Joules per Kelvin (NIST 2018)
pub const BOLTZMANN_K: f64 = 1.380649e-23;

/// Standard operating temperature for silicon CMOS (°C → Kelvin)
pub const CMOS_TEMP_K: f64 = 300.0; // 27°C room temperature

/// Minimum heat dissipation per bit erasure at room temperature (Joules)
/// E_min = k_B * T * ln(2) = 1.38e-23 * 300 * 0.693 = 2.87e-21 J
pub const LANDAUER_LIMIT_J: f64 = BOLTZMANN_K * CMOS_TEMP_K * LN_2;

// ============================================================
// Logic Gate Model
// ============================================================

/// The type of a classical logic gate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GateType {
    // Irreversible gates (erase information → generate heat)
    And,
    Or,
    Nand,
    Nor,
    Xor,
    Xnor,
    Not,
    Buffer,
    // Reversible gates (zero information erasure → zero Landauer heat)
    Toffoli,  // CCNOT — universal reversible gate, simulates AND
    Fredkin,  // CSWAP — controlled swap, simulates OR
    Cnot,     // Controlled-NOT, simulates XOR
    PauliX,   // Quantum NOT gate (reversible)
}

impl GateType {
    /// Returns the number of input bits erased by this gate per evaluation.
    /// An irreversible N-input gate maps 2^N inputs to 2^M outputs (M < N) → erases N-M bits.
    pub fn bits_erased(&self) -> f64 {
        match self {
            // AND(a,b) → c: 2 inputs → 1 output. We lose which (a,b) pair produced c.
            // The information lost: H_in - H_out = log2(4) - log2(2) = 1 bit erased.
            GateType::And  => 1.0,
            GateType::Or   => 1.0,
            GateType::Nand => 1.0,
            GateType::Nor  => 1.0,
            // XOR(a,b) → c: While c is 1-bit, knowing c doesn't tell you which (a,b).
            // Still erases 1 bit.
            GateType::Xor  => 1.0,
            GateType::Xnor => 1.0,
            // NOT(a) → !a: 1 input, 1 output. Bijection. Reversible. BUT in CMOS, the
            // transistor switching still dissipates dynamic power (CV²f). Zero Landauer heat.
            GateType::Not  => 0.0,
            GateType::Buffer => 0.0,
            // Reversible gates: bijections — no information loss, zero Landauer heat.
            GateType::Toffoli => 0.0,
            GateType::Fredkin => 0.0,
            GateType::Cnot    => 0.0,
            GateType::PauliX  => 0.0,
        }
    }

    /// Returns true if this gate is logically reversible.
    pub fn is_reversible(&self) -> bool {
        self.bits_erased() == 0.0
    }

    /// The reversible equivalent of this irreversible gate.
    pub fn reversible_equivalent(&self) -> Option<(GateType, &'static str)> {
        match self {
            GateType::And  => Some((GateType::Toffoli, "Toffoli(A, B, 0) → (A, B, A∧B) [ancilla bit required]")),
            GateType::Or   => Some((GateType::Fredkin, "Fredkin(1, A, B) → (1, A∧¬B∨A∧B, ...) [CSWAP formulation]")),
            GateType::Nand => Some((GateType::Toffoli, "Toffoli(A, B, 1) → (A, B, ¬(A∧B)) [NAND via Toffoli with flipped ancilla]")),
            GateType::Nor  => Some((GateType::Fredkin, "Fredkin(0, A, B) followed by NOT [NOR decomposition]")),
            GateType::Xor  => Some((GateType::Cnot, "CNOT(A, B) → (A, A⊕B) [zero ancilla XOR]")),
            GateType::Xnor => Some((GateType::Cnot, "CNOT(A, B) followed by PauliX → XNOR")),
            _ => None,
        }
    }
}

// ============================================================
// Circuit Representation
// ============================================================

/// A single gate node in the circuit graph.
#[derive(Debug, Clone)]
pub struct GateNode {
    pub id: usize,
    pub gate_type: GateType,
    /// Input wire IDs connecting to this gate
    pub inputs: Vec<usize>,
    /// Output wire IDs
    pub outputs: Vec<usize>,
    /// Evaluated name (e.g., from AST node text)
    pub ast_label: String,
}

/// A full logic circuit composed of gate nodes.
#[derive(Debug, Clone)]
pub struct LogicCircuit {
    pub nodes: Vec<GateNode>,
    pub input_count: usize,
    pub output_count: usize,
    pub name: String,
}

impl LogicCircuit {
    pub fn new(name: &str, inputs: usize, outputs: usize) -> Self {
        Self {
            nodes: Vec::new(),
            input_count: inputs,
            output_count: outputs,
            name: name.to_string(),
        }
    }

    pub fn add_gate(&mut self, gate: GateType, inputs: Vec<usize>, outputs: Vec<usize>, label: &str) -> usize {
        let id = self.nodes.len();
        self.nodes.push(GateNode { id, gate_type: gate, inputs, outputs, ast_label: label.to_string() });
        id
    }

    /// Count the total number of irreversible gates in this circuit.
    pub fn irreversible_gate_count(&self) -> usize {
        self.nodes.iter().filter(|n| !n.gate_type.is_reversible()).count()
    }

    /// Total bits erased by this circuit per clock cycle.
    pub fn total_bits_erased(&self) -> f64 {
        self.nodes.iter().map(|n| n.gate_type.bits_erased()).sum()
    }
}

// ============================================================
// Thermodynamic Analyzer
// ============================================================

/// The full result of a thermodynamic analysis of a logic circuit.
#[derive(Debug, Clone)]
pub struct ThermodynamicAnalysis {
    pub circuit_name: String,
    pub temperature_k: f64,
    pub total_gates: usize,
    pub irreversible_gates: usize,
    pub reversible_gates: usize,
    pub total_bits_erased_per_cycle: f64,
    /// Minimum heat dissipation per clock cycle (Joules) — Landauer limit
    pub min_heat_per_cycle_joules: f64,
    /// Heat in femtojoules (fJ) — more practical unit for chip analysis
    pub min_heat_per_cycle_femtojoules: f64,
    /// Estimated Shannon entropy loss (bits per cycle)
    pub entropy_loss_bits: f64,
    /// Whether the circuit could theoretically be made thermodynamically reversible
    pub fully_reversible_possible: bool,
    /// The suggested reversible circuit decomposition
    pub reversible_circuit: Option<LogicCircuit>,
    /// Gate-level irreversibility report
    pub gate_analysis: Vec<GateAnalysisResult>,
}

#[derive(Debug, Clone)]
pub struct GateAnalysisResult {
    pub gate_id: usize,
    pub gate_label: String,
    pub gate_type: GateType,
    pub is_reversible: bool,
    pub heat_joules: f64,
    pub suggestion: Option<String>,
}

/// Full thermodynamic analysis engine for logic circuits.
pub struct ThermodynamicsAnalyzer {
    pub temperature_kelvin: f64,
}

impl ThermodynamicsAnalyzer {
    pub fn new(temperature_kelvin: f64) -> Self {
        let temp = if !temperature_kelvin.is_finite() || temperature_kelvin < 0.0 {
            CMOS_TEMP_K
        } else {
            temperature_kelvin
        };
        Self { temperature_kelvin: temp }
    }

    pub fn at_room_temperature() -> Self {
        Self::new(CMOS_TEMP_K)
    }

    /// Minimum heat dissipated by erasing a single bit at this temperature (Joules).
    pub fn landauer_energy_per_bit(&self) -> f64 {
        BOLTZMANN_K * self.temperature_kelvin * LN_2
    }

    /// Total minimum heat dissipated per clock cycle by the given circuit.
    pub fn minimum_heat_dissipation(&self, bits_erased: usize) -> f64 {
        self.landauer_energy_per_bit() * bits_erased as f64
    }

    /// Convenience method: simulate the Landauer limit for a circuit with a given number of gates
    /// and erased bits. Returns a `LandauerReport` suitable for the REST API and Tauri commands.
    ///
    /// `total_gates`   — total number of logic gates in the simulated circuit.
    /// `erased_bits`   — number of those gates that are irreversible (each erases ≥1 bit).
    ///
    /// This models a worst-case irreversible CMOS circuit and computes whether the thermal
    /// side-channel signal would be detectable by a sensitive IR or Peltier sensor (threshold: 1 fJ).
    pub fn simulate_landauer_limit(&self, total_gates: usize, erased_bits: usize) -> LandauerReport {
        let erased = erased_bits.min(total_gates); // Clamp: can't erase more bits than gates
        let joules_per_bit = self.landauer_energy_per_bit();
        let total_joules = joules_per_bit * erased as f64;
        let total_fj = total_joules * 1e15;
        let irreversible_fraction = if total_gates > 0 {
            erased as f64 / total_gates as f64
        } else {
            0.0
        };

        LandauerReport {
            temperature_kelvin: self.temperature_kelvin,
            landauer_limit_joules: joules_per_bit,
            total_dissipation_joules: total_joules,
            total_dissipation_femtojoules: total_fj,
            irreversible_fraction,
            // 1 fJ = 1e-15 J is the approximate lower bound of practical IR camera sensitivity
            thermal_side_channel_risk: total_joules > 1e-15,
        }
    }

    /// Analyze a complete logic circuit for thermodynamic reversibility.
    pub fn analyze_circuit(&self, circuit: &LogicCircuit) -> ThermodynamicAnalysis {
        let mut gate_analysis = Vec::new();
        let mut total_bits_erased = 0.0f64;
        let mut fully_reversible = true;
        let mut reversible_circuit = LogicCircuit::new(&format!("{}_reversible", circuit.name), circuit.input_count, circuit.output_count);

        for node in &circuit.nodes {
            let heat = self.landauer_energy_per_bit() * node.gate_type.bits_erased();
            let suggestion = node.gate_type.reversible_equivalent()
                .map(|(_, desc)| desc.to_string());

            if !node.gate_type.is_reversible() {
                fully_reversible = false;
                // Add the reversible equivalent to the reversible circuit
                if let Some((rev_gate, _)) = node.gate_type.reversible_equivalent() {
                    reversible_circuit.add_gate(
                        rev_gate,
                        node.inputs.clone(),
                        node.outputs.clone(),
                        &node.ast_label,
                    );
                }
            } else {
                reversible_circuit.add_gate(
                    node.gate_type.clone(),
                    node.inputs.clone(),
                    node.outputs.clone(),
                    &node.ast_label,
                );
            }

            total_bits_erased += node.gate_type.bits_erased();

            gate_analysis.push(GateAnalysisResult {
                gate_id: node.id,
                gate_label: node.ast_label.clone(),
                gate_type: node.gate_type.clone(),
                is_reversible: node.gate_type.is_reversible(),
                heat_joules: heat,
                suggestion,
            });
        }

        let total_heat_j = self.landauer_energy_per_bit() * total_bits_erased;
        let total_heat_fj = total_heat_j * 1e15; // Convert to femtojoules

        ThermodynamicAnalysis {
            circuit_name: circuit.name.clone(),
            temperature_k: self.temperature_kelvin,
            total_gates: circuit.nodes.len(),
            irreversible_gates: circuit.irreversible_gate_count(),
            reversible_gates: circuit.nodes.len() - circuit.irreversible_gate_count(),
            total_bits_erased_per_cycle: total_bits_erased,
            min_heat_per_cycle_joules: total_heat_j,
            min_heat_per_cycle_femtojoules: total_heat_fj,
            entropy_loss_bits: total_bits_erased,
            fully_reversible_possible: true, // In theory, any circuit can be made reversible
            reversible_circuit: if fully_reversible { None } else { Some(reversible_circuit) },
            gate_analysis,
        }
    }

    /// Parse a string list of AST gate node names and build a LogicCircuit automatically.
    /// This is the entry point for analysis driven by the Tree-sitter scanner output.
    pub fn build_circuit_from_ast_nodes(&self, ast_nodes: &[&str], circuit_name: &str) -> LogicCircuit {
        let mut circuit = LogicCircuit::new(circuit_name, ast_nodes.len(), ast_nodes.len());
        for (i, &node) in ast_nodes.iter().enumerate() {
            let gate = match node.to_uppercase().as_str() {
                "AND"    => GateType::And,
                "OR"     => GateType::Or,
                "NAND"   => GateType::Nand,
                "NOR"    => GateType::Nor,
                "XOR"    => GateType::Xor,
                "XNOR"   => GateType::Xnor,
                "NOT"    => GateType::Not,
                "BUFFER" => GateType::Buffer,
                "TOFFOLI" => GateType::Toffoli,
                "FREDKIN" => GateType::Fredkin,
                "CNOT"   => GateType::Cnot,
                _        => GateType::Buffer, // Unknown nodes map to a no-op buffer
            };
            circuit.add_gate(gate, vec![i], vec![i], node);
        }
        circuit
    }

    /// Convert irreversible AST nodes to their reversible equivalents (string representation).
    /// Compatible API for the previous simple version.
    pub fn transpile_to_reversible_logic(&self, irreversible_ast_nodes: &[&str]) -> Vec<String> {
        let circuit = self.build_circuit_from_ast_nodes(irreversible_ast_nodes, "transpile_target");
        let analysis = self.analyze_circuit(&circuit);

        analysis.gate_analysis.iter().map(|g| {
            if let Some(suggestion) = &g.suggestion {
                format!("IRREVERSIBLE → REVERSIBLE: {}: {}", g.gate_label, suggestion)
            } else {
                format!("REVERSIBLE: {}: No substitution needed", g.gate_label)
            }
        }).collect()
    }

    /// Generate a human-readable thermodynamic report.
    pub fn generate_report(&self, analysis: &ThermodynamicAnalysis) -> String {
        let mut report = format!(
            "═══════════════════════════════════════════════════════\n\
             PQCanary Thermodynamic Reversibility Report\n\
             Circuit: {}\n\
             Operating Temperature: {:.1} K ({:.1} °C)\n\
             ═══════════════════════════════════════════════════════\n\n",
            analysis.circuit_name,
            analysis.temperature_k,
            analysis.temperature_k - 273.15
        );

        report.push_str(&format!(
            "SUMMARY\n\
             ───────\n\
             Total Gates:          {}\n\
             Irreversible Gates:   {} ({:.1}%)\n\
             Reversible Gates:     {} ({:.1}%)\n\
             Bits Erased/Cycle:    {:.2} bits\n\
             Min Heat/Cycle:       {:.4} fJ  (Landauer Limit)\n\
             Shannon Entropy Loss: {:.2} bits/cycle\n\n",
            analysis.total_gates,
            analysis.irreversible_gates,
            if analysis.total_gates > 0 {
                analysis.irreversible_gates as f64 / analysis.total_gates as f64 * 100.0
            } else { 0.0 },
            analysis.reversible_gates,
            if analysis.total_gates > 0 {
                analysis.reversible_gates as f64 / analysis.total_gates as f64 * 100.0
            } else { 0.0 },
            analysis.total_bits_erased_per_cycle,
            analysis.min_heat_per_cycle_femtojoules,
            analysis.entropy_loss_bits
        ));

        report.push_str("GATE-LEVEL ANALYSIS\n───────────────────\n");
        for g in &analysis.gate_analysis {
            let rev_str = if g.is_reversible { "REVERSIBLE" } else { "IRREVERSIBLE" };
            report.push_str(&format!("  {} {:?} ({}) — {:.4e} J heat/cycle\n", rev_str, g.gate_type, g.gate_label, g.heat_joules));
            if let Some(sug) = &g.suggestion {
                report.push_str(&format!("       → Substitute with: {}\n", sug));
            }
        }

        if analysis.irreversible_gates > 0 {
            report.push_str(
                "\nWARN: THERMAL SIDE-CHANNEL RISK DETECTED\n\
                 This circuit dissipates measurable heat per clock cycle.\n\
                 An adversary with a sufficiently sensitive thermal sensor (Peltier/IR camera)\n\
                 could infer computational state from thermal emanations.\n\
                 Recommendation: Replace all irreversible gates with their reversible equivalents.\n"
            );
        } else {
            report.push_str(
                "\nOK: THERMODYNAMICALLY CLEAN\n\
                 All gates are reversible. Zero Landauer heat dissipation.\n\
                 This circuit is immune to thermal side-channel attacks.\n"
            );
        }

        report
    }
}
