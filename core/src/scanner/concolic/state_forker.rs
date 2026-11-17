use std::collections::{HashMap, VecDeque};
use crate::scanner::concolic::memory_model::SymbolicMemoryModel;
use crate::scanner::concolic::smt_builder::SmtConstraintTree;

/// A single forked execution universe.
/// Each contains its own independent memory snapshot, constraint set, and instruction pointer.
#[derive(Debug, Clone)]
pub struct ExecutionState {
    pub state_id: u64,
    pub memory: SymbolicMemoryModel,
    pub constraints: SmtConstraintTree,
    /// Index into the SSA instruction list where this state resumes execution.
    pub instruction_pointer: usize,
    /// Monotonic depth counter — used by the path explosion mitigator.
    pub path_depth: u32,
    /// The concrete register file (SSA variable name → concrete i64 value where known).
    pub concrete_regs: HashMap<String, i64>,
    /// Symbolic register file (SSA variable name → SMT expression where symbolic).
    pub symbolic_regs: HashMap<String, String>,
    /// Human-readable path condition summary (for debugging and reporting).
    pub path_summary: Vec<String>,
}

impl ExecutionState {
    /// Construct the initial execution state for a fresh analysis run.
    pub fn initial(instruction_pointer: usize) -> Self {
        Self {
            state_id: 0,
            memory: SymbolicMemoryModel::new(),
            constraints: SmtConstraintTree::new(),
            instruction_pointer,
            path_depth: 0,
            concrete_regs: HashMap::new(),
            symbolic_regs: HashMap::new(),
            path_summary: Vec::new(),
        }
    }

    /// Record the concrete value of an SSA variable in this state's register file.
    pub fn set_concrete(&mut self, var: &str, val: i64) {
        self.concrete_regs.insert(var.to_string(), val);
    }

    /// Query whether this state's register file has a concrete value for a given SSA variable.
    pub fn get_concrete(&self, var: &str) -> Option<i64> {
        self.concrete_regs.get(var).copied()
    }

    /// Mark an SSA variable as pointing to a symbolic SMT expression name.
    pub fn set_symbolic(&mut self, var: &str, smt_var: &str) {
        self.symbolic_regs.insert(var.to_string(), smt_var.to_string());
    }

    /// Append a description of the branch taken to the human-readable path summary.
    pub fn record_branch(&mut self, description: &str) {
        self.path_summary.push(description.to_string());
    }
}

/// Path explosion mitigation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplosionStrategy {
    /// Standard BFS — explore all states breadth-first (exhaustive, may be slow).
    BreadthFirst,
    /// Depth-bounded DFS — prioritize deep paths but cap at max_depth.
    DepthBounded { max_depth: u32 },
    /// Coverage-guided — prioritize states that cover new SSA instruction indices.
    CoverageGuided,
}

/// The Path Explosion Mitigator and State Fork Manager.
///
/// When the SSA interpreter hits a conditional branch instruction, it creates two
/// independent child states (one for the true branch, one for the false branch), each
/// inheriting the full memory model and constraint set of their parent — analogous to
/// how KLEE operates internally.
pub struct StateForker {
    /// The active worklist of states pending symbolic execution.
    pub worklist: VecDeque<ExecutionState>,
    /// Set of fully explored states (for coverage tracking).
    pub completed_states: Vec<ExecutionState>,
    /// SSA instruction indices that have been covered by at least one state.
    covered_instructions: std::collections::HashSet<usize>,
    /// Global state ID counter.
    state_counter: u64,
    /// Path explosion control strategy.
    strategy: ExplosionStrategy,
    /// Maximum number of states to ever hold in the worklist simultaneously.
    max_worklist_size: usize,
}

impl Default for StateForker {
    fn default() -> Self {
        Self::new()
    }
}

impl StateForker {
    pub fn new() -> Self {
        Self {
            worklist: VecDeque::new(),
            completed_states: Vec::new(),
            covered_instructions: std::collections::HashSet::new(),
            state_counter: 0,
            strategy: ExplosionStrategy::DepthBounded { max_depth: 50 },
            max_worklist_size: 1024,
        }
    }

    pub fn with_strategy(mut self, strategy: ExplosionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn with_max_worklist(mut self, size: usize) -> Self {
        self.max_worklist_size = size;
        self
    }

    /// Enqueue the initial state onto the worklist.
    pub fn seed(&mut self, initial: ExecutionState) {
        self.worklist.push_back(initial);
    }

    /// Pop the next state to execute based on the active strategy.
    pub fn next_state(&mut self) -> Option<ExecutionState> {
        match self.strategy {
            ExplosionStrategy::BreadthFirst => self.worklist.pop_front(),
            ExplosionStrategy::DepthBounded { .. } => self.worklist.pop_back(), // LIFO = DFS
            ExplosionStrategy::CoverageGuided => {
                if self.worklist.is_empty() {
                    return None;
                }
                // Find the state that covers the most previously unseen instructions
                let mut best_idx = 0;
                let mut best_score = 0usize;
                for (idx, state) in self.worklist.iter().enumerate() {
                    let uncovered = if self.covered_instructions.contains(&state.instruction_pointer) {
                        0
                    } else {
                        1
                    };
                    if uncovered > best_score {
                        best_score = uncovered;
                        best_idx = idx;
                    }
                }
                self.worklist.remove(best_idx)
            }
        }
    }

    /// Check if a state should be pruned before forking.
    pub fn should_prune(&self, state: &ExecutionState) -> bool {
        // Enforce depth cap
        if let ExplosionStrategy::DepthBounded { max_depth } = self.strategy {
            if state.path_depth >= max_depth {
                return true;
            }
        }
        // Enforce worklist size cap (prevents memory explosion)
        self.worklist.len() >= self.max_worklist_size
    }

    /// Fork the current state at a conditional branch.
    ///
    /// Returns two new independent states:
    ///   - `true_state`:  constraints extended with the condition being TRUE.
    ///   - `false_state`: constraints extended with the condition being FALSE (negated).
    ///
    /// The condition_smt is a pre-compiled SMT-LIB2 expression string.
    pub fn fork(
        &mut self,
        parent: &ExecutionState,
        condition_smt: &str,
        true_ip: usize,
        false_ip: usize,
        branch_description: &str,
    ) -> (ExecutionState, ExecutionState) {
        let mut true_state = parent.clone();
        true_state.state_id = self.next_id();
        true_state.instruction_pointer = true_ip;
        true_state.path_depth += 1;
        true_state.constraints.add_raw_assertion(
            crate::scanner::concolic::smt_builder::SmtExpr::Var(condition_smt.to_string())
        );
        true_state.record_branch(&format!("{} → TRUE", branch_description));

        let mut false_state = parent.clone();
        false_state.state_id = self.next_id();
        false_state.instruction_pointer = false_ip;
        false_state.path_depth += 1;
        false_state.constraints.add_raw_assertion(
            crate::scanner::concolic::smt_builder::SmtExpr::Not(
                Box::new(crate::scanner::concolic::smt_builder::SmtExpr::Var(condition_smt.to_string()))
            )
        );
        false_state.record_branch(&format!("{} → FALSE", branch_description));

        (true_state, false_state)
    }

    /// Record that a state has finished execution (reached a terminal instruction or pruned).
    pub fn complete_state(&mut self, state: ExecutionState) {
        self.covered_instructions.insert(state.instruction_pointer);
        self.completed_states.push(state);
    }

    /// Returns the total count of states that have been forked across the session.
    pub fn total_states_explored(&self) -> u64 {
        self.state_counter
    }

    /// Returns the coverage percentage of the total instruction count.
    pub fn instruction_coverage(&self, total_instructions: usize) -> f64 {
        if total_instructions == 0 { return 0.0; }
        (self.covered_instructions.len() as f64 / total_instructions as f64) * 100.0
    }

    fn next_id(&mut self) -> u64 {
        self.state_counter += 1;
        self.state_counter
    }
}
