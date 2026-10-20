pub mod ssa_lifter;
pub mod memory_model;
pub mod state_forker;
pub mod smt_builder;
pub mod z3_bridge;

use crate::SecureMaterial;
use ssa_lifter::{SsaLifter, SsaInstruction};
use smt_builder::SmtExpr;
use state_forker::{StateForker, ExecutionState, ExplosionStrategy};
use z3_bridge::{Z3SolverSession, Z3Result};
use std::collections::HashMap;

/// Vulnerability finding reported by the concolic engine.
#[derive(Debug, Clone)]
pub struct ConcolicFinding {
    /// The file path and line where the vulnerability was located.
    pub location: String,
    /// A human-readable description of the finding.
    pub description: String,
    /// The concrete witness input values that prove the vulnerability is reachable.
    /// Maps symbolic variable name → concrete value string from Z3's model.
    pub witness: HashMap<String, String>,
    /// The full path condition (branch decisions taken to reach the bug).
    pub path_condition: Vec<String>,
    /// Severity: how critical is this finding.
    pub severity: FindingSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingSeverity {
    Critical,   // Buffer overflow, use-after-free
    High,       // Timing side-channel
    Medium,     // Integer overflow reachable
    Info,       // Informational coverage note
}

impl ConcolicFinding {
    pub fn to_secure_material(&self) -> SecureMaterial {
        SecureMaterial::new(
            self.description.as_bytes().to_vec(),
            &self.location,
            0,
        )
    }
}

/// Configuration for the orchestrator.
pub struct ConcolicConfig {
    pub strategy: ExplosionStrategy,
    pub max_worklist: usize,
    pub z3_timeout_secs: u64,
}

impl Default for ConcolicConfig {
    fn default() -> Self {
        Self {
            strategy: ExplosionStrategy::DepthBounded { max_depth: 50 },
            max_worklist: 512,
            z3_timeout_secs: 10,
        }
    }
}

/// The Concolic Execution Orchestrator.
///
/// Ties together:
///   1. SsaLifter: translates Tree-sitter AST → SSA IR
///   2. StateForker: manages the worklist and forks states at branches
///   3. SmtConstraintTree: accumulates path constraints as SMT-LIB2 expressions
///   4. Z3SolverSession: physically pipes constraints to the Z3 daemon and reads results
///
/// The engine walks the SSA instruction list, concretely executing where possible
/// and symbolically tracking attacker-controlled inputs. At each branch, it forks
/// two independent states and queries Z3 to determine exploitability.
pub struct ConcolicOrchestrator {
    pub forker: StateForker,
    config: ConcolicConfig,
}

impl ConcolicOrchestrator {
    pub fn new(config: ConcolicConfig) -> Self {
        let forker = StateForker::new()
            .with_strategy(config.strategy)
            .with_max_worklist(config.max_worklist);
        Self { forker, config }
    }

    /// Entry point: lift the provided source code via Tree-sitter, build the SSA IR,
    /// seed the initial state, and run the full symbolic execution loop.
    pub fn analyze_source(
        &mut self,
        source_code: &str,
        file_path: &str,
    ) -> Result<Vec<ConcolicFinding>, String> {
        // Phase 1: Parse source into Tree-sitter AST and lift to SSA
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_javascript::language())
            .map_err(|_| "Failed to load JavaScript grammar for concolic engine".to_string())?;

        let tree = parser.parse(source_code, None)
            .ok_or("Tree-sitter failed to parse source for concolic analysis".to_string())?;

        let mut lifter = SsaLifter::new();
        lifter.lift_ast(tree.root_node(), source_code)
            .map_err(|e| format!("SSA lift error: {}", e))?;

        let instructions = lifter.instructions;
        if instructions.is_empty() {
            return Ok(vec![]);
        }

        // Precompute label index map for O(1) jump and branch resolution
        let mut label_map: HashMap<String, usize> = HashMap::new();
        for (idx, instr) in instructions.iter().enumerate() {
            if let SsaInstruction::Label(name) = instr {
                label_map.insert(name.clone(), idx);
            }
        }

        // Phase 2: Seed the initial state with symbolic input buffers
        let mut initial_state = ExecutionState::initial(0);

        // Declare symbolic inputs: model the first 64 bytes of any user-controlled buffer
        // as independently symbolic bytes that Z3 can assign arbitrary values to.
        for i in 0..64usize {
            let sym_name = format!("user_input_{}", i);
            initial_state.constraints.declare_symbolic_byte(&sym_name);
            initial_state.set_symbolic(&format!("arg_{}", i), &sym_name);
        }

        self.forker.seed(initial_state);

        // Phase 3: Open a persistent Z3 session with configured timeout
        let mut z3 = Z3SolverSession::new()
            .map_err(|e| format!("Z3 IPC error: {}", e))?;

        // Wire the configured timeout — Z3 enforces this per-check-sat call
        z3 = z3.with_timeout(std::time::Duration::from_secs(self.config.z3_timeout_secs));

        let mut findings: Vec<ConcolicFinding> = Vec::new();

        // Phase 4: The main symbolic execution worklist loop
        while let Some(state) = self.forker.next_state() {
            if self.forker.should_prune(&state) {
                self.forker.complete_state(state);
                continue;
            }

            let new_findings = self.step_execute(
                state,
                &instructions,
                &label_map,
                &mut z3,
                file_path,
            )?;

            findings.extend(new_findings);
        }

        Ok(findings)
    }

    /// Execute one SSA instruction in the given state, potentially forking or generating findings.
    fn step_execute(
        &mut self,
        mut state: ExecutionState,
        instructions: &[SsaInstruction],
        label_map: &HashMap<String, usize>,
        z3: &mut Z3SolverSession,
        file_path: &str,
    ) -> Result<Vec<ConcolicFinding>, String> {
        let mut findings = Vec::new();
        let ip = state.instruction_pointer;

        if ip >= instructions.len() {
            self.forker.complete_state(state);
            return Ok(findings);
        }

        let instruction = &instructions[ip];

        match instruction {
            SsaInstruction::AssignLiteral(target, value) => {
                state.set_concrete(target, *value);
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Assign(target, source) => {
                if let Some(concrete) = state.get_concrete(source) {
                    state.set_concrete(target, concrete);
                } else if let Some(sym) = state.symbolic_regs.get(source).cloned() {
                    state.set_symbolic(target, &sym);
                }
                if state.constraints.taint.is_tainted(source) {
                    state.constraints.taint.taint(target);
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Add(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        // Detect concrete integer overflow
                        let result = l.checked_add(r);
                        if result.is_none() {
                            findings.push(ConcolicFinding {
                                location: file_path.to_string(),
                                description: format!("Integer overflow detected: {} + {} overflows i64", l, r),
                                witness: HashMap::new(),
                                path_condition: state.path_summary.clone(),
                                severity: FindingSeverity::Medium,
                            });
                        }
                        state.set_concrete(target, result.unwrap_or(i64::MAX));
                    }
                    _ => {
                        // Symbolic result: propagate taint
                        state.constraints.taint.propagate_binary(
                            lhs, rhs, target
                        );
                        state.set_symbolic(target, &format!("sym_add_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Sub(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        let result = l.checked_sub(r);
                        if result.is_none() {
                            findings.push(ConcolicFinding {
                                location: file_path.to_string(),
                                description: format!("Integer underflow detected: {} - {} underflows i64", l, r),
                                witness: HashMap::new(),
                                path_condition: state.path_summary.clone(),
                                severity: FindingSeverity::Medium,
                            });
                        }
                        state.set_concrete(target, result.unwrap_or(i64::MIN));
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_sub_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Mul(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        let result = l.checked_mul(r);
                        if result.is_none() {
                            findings.push(ConcolicFinding {
                                location: file_path.to_string(),
                                description: format!("Integer multiplication overflow detected: {} * {} overflows i64", l, r),
                                witness: HashMap::new(),
                                path_condition: state.path_summary.clone(),
                                severity: FindingSeverity::Medium,
                            });
                        }
                        state.set_concrete(target, result.unwrap_or(i64::MAX));
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_mul_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Div(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(_), Some(0)) => {
                        findings.push(ConcolicFinding {
                            location: file_path.to_string(),
                            description: format!("Division by zero detected in SSA expression: divisor '{}' is 0", rhs),
                            witness: HashMap::new(),
                            path_condition: state.path_summary.clone(),
                            severity: FindingSeverity::High,
                        });
                        state.set_concrete(target, 0);
                    }
                    (Some(l), Some(r)) => {
                        let result = l.checked_div(r);
                        state.set_concrete(target, result.unwrap_or(0));
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_div_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Mod(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(_), Some(0)) => {
                        findings.push(ConcolicFinding {
                            location: file_path.to_string(),
                            description: format!("Modulo by zero detected in SSA expression: divisor '{}' is 0", rhs),
                            witness: HashMap::new(),
                            path_condition: state.path_summary.clone(),
                            severity: FindingSeverity::High,
                        });
                        state.set_concrete(target, 0);
                    }
                    (Some(l), Some(r)) => {
                        let result = l.checked_rem(r);
                        state.set_concrete(target, result.unwrap_or(0));
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_mod_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::BitAnd(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, l & r);
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_and_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::BitOr(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, l | r);
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_or_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::BitXor(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, l ^ r);
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_xor_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Shl(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) if (0..64).contains(&r) => {
                        let res = l.checked_shl(r as u32).unwrap_or(0);
                        state.set_concrete(target, res);
                    }
                    (Some(_), Some(_)) => {
                        state.set_concrete(target, 0);
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_shl_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Shr(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) if (0..64).contains(&r) => {
                        let res = l.checked_shr(r as u32).unwrap_or(0);
                        state.set_concrete(target, res);
                    }
                    (Some(_), Some(_)) => {
                        state.set_concrete(target, 0);
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_shr_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Lt(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l < r { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_lt_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Le(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l <= r { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_le_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Gt(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l > r { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_gt_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Ge(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l >= r { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_ge_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Eq(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l == r { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_eq_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Ne(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l != r { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_ne_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::LogicalAnd(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l != 0 && r != 0 { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_land_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::LogicalOr(target, lhs, rhs) => {
                match (state.get_concrete(lhs), state.get_concrete(rhs)) {
                    (Some(l), Some(r)) => {
                        state.set_concrete(target, if l != 0 || r != 0 { 1 } else { 0 });
                    }
                    _ => {
                        state.constraints.taint.propagate_binary(lhs, rhs, target);
                        state.set_symbolic(target, &format!("sym_lor_{}", target));
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Load(target, src) => {
                if let Some(concrete) = state.get_concrete(src) {
                    state.set_concrete(target, concrete);
                } else if let Some(sym) = state.symbolic_regs.get(src).cloned() {
                    state.set_symbolic(target, &sym);
                }
                if state.constraints.taint.is_tainted(src) {
                    state.constraints.taint.taint(target);
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Store(target, src) => {
                if let Some(concrete) = state.get_concrete(src) {
                    state.set_concrete(target, concrete);
                } else if let Some(sym) = state.symbolic_regs.get(src).cloned() {
                    state.set_symbolic(target, &sym);
                }
                if state.constraints.taint.is_tainted(src) {
                    state.constraints.taint.taint(target);
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Alloc(target, size) => {
                if let Ok(ptr) = state.memory.malloc(*size) {
                    state.set_concrete(target, ptr as i64);
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Phi(target, sources) => {
                let mut any_tainted = false;
                let mut first_concrete: Option<i64> = None;
                let mut all_same = true;
                for src in sources {
                    if state.constraints.taint.is_tainted(src) {
                        any_tainted = true;
                    }
                    if let Some(c) = state.get_concrete(src) {
                        match first_concrete {
                            None => first_concrete = Some(c),
                            Some(prev) if prev != c => all_same = false,
                            _ => {}
                        }
                    } else {
                        all_same = false;
                    }
                }
                if any_tainted {
                    state.constraints.taint.taint(target);
                    state.set_symbolic(target, &format!("sym_phi_{}", target));
                } else if all_same {
                    if let Some(concrete_val) = first_concrete {
                        state.set_concrete(target, concrete_val);
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::AssertLess(index_var, bound_var) => {
                // This is the critical bounds check instruction from the SSA lifter.
                // We query Z3: is it possible that index >= bound? If SAT → buffer overflow proven.
                let is_symbolic_index = state.constraints.taint.is_tainted(index_var);

                if is_symbolic_index {
                    let mut query_constraints = state.constraints.clone();

                    // Assert the NEGATION of the bounds check (i.e., assert the overflow occurs)
                    let sym_idx = SmtExpr::Var(
                        state.symbolic_regs.get(index_var)
                            .cloned()
                            .unwrap_or_else(|| index_var.clone())
                    );
                    let bound_val = state.get_concrete(bound_var).unwrap_or(128);
                    let bound_expr = SmtExpr::BitVecLit(bound_val, 8);

                    // index >= bound means out-of-bounds access
                    query_constraints.add_raw_assertion(SmtExpr::BvUGe(
                        Box::new(sym_idx),
                        Box::new(bound_expr),
                    ));

                    let script = query_constraints.compile_to_smtlib2();
                    match z3.query(&script)? {
                        Z3Result::Sat(witness) => {
                            findings.push(ConcolicFinding {
                                location: file_path.to_string(),
                                description: format!(
                                    "CRITICAL: Symbolic buffer overflow proven. Index '{}' can exceed bound '{}'. \
                                     Z3 witness: {:?}",
                                    index_var, bound_var, witness
                                ),
                                witness,
                                path_condition: state.path_summary.clone(),
                                severity: FindingSeverity::Critical,
                            });
                        }
                        Z3Result::Unsat => {
                            // Bounds check is mathematically safe — no overflow possible
                        }
                        Z3Result::Timeout => {
                            findings.push(ConcolicFinding {
                                location: file_path.to_string(),
                                description: format!(
                                    "Z3 timeout on bounds check for '{}'. Could not prove safety.",
                                    index_var
                                ),
                                witness: HashMap::new(),
                                path_condition: state.path_summary.clone(),
                                severity: FindingSeverity::Info,
                            });
                        }
                        Z3Result::Unknown(msg) => {
                            findings.push(ConcolicFinding {
                                location: file_path.to_string(),
                                description: format!("Z3 unknown result: {}", msg),
                                witness: HashMap::new(),
                                path_condition: state.path_summary.clone(),
                                severity: FindingSeverity::Info,
                            });
                        }
                    }
                } else if let Some(idx_val) = state.get_concrete(index_var) {
                    let bound_val = state.get_concrete(bound_var).unwrap_or(128);
                    if idx_val >= bound_val {
                        findings.push(ConcolicFinding {
                            location: file_path.to_string(),
                            description: format!(
                                "CRITICAL: Concrete buffer overflow detected: index {} >= bound {}",
                                idx_val, bound_val
                            ),
                            witness: HashMap::new(),
                            path_condition: state.path_summary.clone(),
                            severity: FindingSeverity::Critical,
                        });
                    }
                }

                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::AssertGreaterEq(index_var, bound_var) => {
                let is_symbolic_index = state.constraints.taint.is_tainted(index_var);
                if is_symbolic_index {
                    let mut query_constraints = state.constraints.clone();
                    let sym_idx = SmtExpr::Var(
                        state.symbolic_regs.get(index_var)
                            .cloned()
                            .unwrap_or_else(|| index_var.clone())
                    );
                    let bound_val = state.get_concrete(bound_var).unwrap_or(0);
                    let bound_expr = SmtExpr::BitVecLit(bound_val, 8);

                    // Negation: index < bound (signed buffer underflow)
                    query_constraints.add_raw_assertion(SmtExpr::BvSLt(
                        Box::new(sym_idx),
                        Box::new(bound_expr),
                    ));

                    let script = query_constraints.compile_to_smtlib2();
                    if let Ok(Z3Result::Sat(witness)) = z3.query(&script) {
                        findings.push(ConcolicFinding {
                            location: file_path.to_string(),
                            description: format!(
                                "CRITICAL: Symbolic buffer underflow proven. Index '{}' can be less than bound '{}'. Z3 witness: {:?}",
                                index_var, bound_var, witness
                            ),
                            witness,
                            path_condition: state.path_summary.clone(),
                            severity: FindingSeverity::Critical,
                        });
                    }
                } else if let Some(idx_val) = state.get_concrete(index_var) {
                    let bound_val = state.get_concrete(bound_var).unwrap_or(0);
                    if idx_val < bound_val {
                        findings.push(ConcolicFinding {
                            location: file_path.to_string(),
                            description: format!(
                                "CRITICAL: Concrete buffer underflow detected: index {} < bound {}",
                                idx_val, bound_val
                            ),
                            witness: HashMap::new(),
                            path_condition: state.path_summary.clone(),
                            severity: FindingSeverity::Critical,
                        });
                    }
                }
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Branch(cond_var, true_label, false_label) => {
                // Resolve label indices in O(1)
                let true_ip = label_map.get(true_label).copied().unwrap_or(instructions.len());
                let false_ip = label_map.get(false_label).copied().unwrap_or(instructions.len());

                // Fast path: if the condition variable is untainted and concrete,
                // avoid state explosion and only follow the deterministic feasible branch!
                if !state.constraints.taint.is_tainted(cond_var) {
                    if let Some(concrete_val) = state.get_concrete(cond_var) {
                        if concrete_val != 0 {
                            state.instruction_pointer = true_ip;
                            state.path_depth += 1;
                            state.record_branch(&format!("deterministic branch on '{}' != 0 → TRUE", cond_var));
                            self.forker.worklist.push_back(state);
                        } else {
                            state.instruction_pointer = false_ip;
                            state.path_depth += 1;
                            state.record_branch(&format!("deterministic branch on '{}' == 0 → FALSE", cond_var));
                            self.forker.worklist.push_back(state);
                        }
                        return Ok(findings);
                    }
                }

                let cond_smt = state.symbolic_regs.get(cond_var)
                    .cloned()
                    .unwrap_or_else(|| {
                        // Concrete condition: only take the determined branch
                        if state.get_concrete(cond_var).unwrap_or(0) != 0 {
                            "true".to_string()
                        } else {
                            "false".to_string()
                        }
                    });

                let (true_state, false_state) = self.forker.fork(
                    &state,
                    &cond_smt,
                    true_ip,
                    false_ip,
                    &format!("branch on '{}'", cond_var),
                );

                self.forker.worklist.push_back(true_state);
                self.forker.worklist.push_back(false_state);
            }

            SsaInstruction::Jump(target_label) => {
                let target_ip = label_map.get(target_label).copied().unwrap_or(instructions.len());
                state.instruction_pointer = target_ip;
                state.path_depth += 1;
                self.forker.worklist.push_back(state);
            }

            SsaInstruction::Label(_) => {
                state.instruction_pointer += 1;
                self.forker.worklist.push_back(state);
            }
        }

        Ok(findings)
    }

    /// Find the instruction pointer index for a given SSA label name (fallback helper).
    pub fn find_label_ip(&self, instructions: &[SsaInstruction], label_name: &str) -> usize {
        for (idx, instr) in instructions.iter().enumerate() {
            if let SsaInstruction::Label(name) = instr {
                if name == label_name {
                    return idx;
                }
            }
        }
        instructions.len()
    }
}
