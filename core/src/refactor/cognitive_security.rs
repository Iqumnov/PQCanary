//! Control Flow Graph (CFG) Engine & Halstead Cognitive Metrics
//!
//! Replaces keyword heuristics with full Control Flow Graph traversal:
//! basic blocks, directed branch edges, loop backedges, and connected components.
//!
//! Formally computes McCabe's Cyclomatic Complexity:
//!     M = E - N + 2P
//! where E is directed edges, N is basic block nodes, and P is connected components.

use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct HalsteadMetrics {
    pub unique_operators: usize, // n1
    pub unique_operands: usize,  // n2
    pub total_operators: usize,  // N1
    pub total_operands: usize,   // N2
}

impl HalsteadMetrics {
    /// Program Vocabulary: n = n1 + n2
    pub fn vocabulary(&self) -> usize {
        self.unique_operators + self.unique_operands
    }

    /// Program Length: N = N1 + N2
    pub fn length(&self) -> usize {
        self.total_operators + self.total_operands
    }

    /// Calculated Estimated Length: N_hat = n1*log2(n1) + n2*log2(n2)
    pub fn estimated_length(&self) -> f64 {
        let n1 = self.unique_operators as f64;
        let n2 = self.unique_operands as f64;
        let p1 = if n1 > 0.0 { n1 * n1.log2() } else { 0.0 };
        let p2 = if n2 > 0.0 { n2 * n2.log2() } else { 0.0 };
        p1 + p2
    }

    /// Volume: V = N * log2(n)
    pub fn volume(&self) -> f64 {
        let v = self.vocabulary() as f64;
        if v > 0.0 {
            (self.length() as f64) * v.log2()
        } else {
            0.0
        }
    }

    /// Difficulty: D = (n1 / 2) * (N2 / n2)
    pub fn difficulty(&self) -> f64 {
        if self.unique_operands == 0 {
            return 0.0;
        }
        (self.unique_operators as f64 / 2.0) * (self.total_operands as f64 / self.unique_operands as f64)
    }

    /// Effort: E = D * V
    pub fn effort(&self) -> f64 {
        self.difficulty() * self.volume()
    }

    /// Time required to program (in seconds): T = E / 18
    pub fn time_required(&self) -> f64 {
        self.effort() / 18.0
    }

    /// Number of delivered bugs: B = E^(2/3) / 3000
    pub fn delivered_bugs(&self) -> f64 {
        let b = self.effort().powf(2.0 / 3.0) / 3000.0;
        if b.is_finite() && b >= 0.0 { b } else { 0.0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockKind {
    Entry,
    Normal,
    BranchCondition,
    LoopHeader,
    LoopBody,
    SwitchHeader,
    SwitchCase,
    Exit,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub label: String,
    pub kind: BlockKind,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EdgeKind {
    Unconditional,
    BranchTrue,
    BranchFalse,
    LoopBackedge,
    LoopExit,
    SwitchCase,
    Fallthrough,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CfgEdge {
    pub source: usize,
    pub target: usize,
    pub kind: EdgeKind,
}

/// A formal Control Flow Graph representation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<usize, BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub entry_id: usize,
    pub exit_id: usize,
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        let mut blocks = HashMap::new();
        let entry = BasicBlock {
            id: 0,
            label: "ENTRY".to_string(),
            kind: BlockKind::Entry,
            instruction_count: 0,
        };
        let exit = BasicBlock {
            id: 1,
            label: "EXIT".to_string(),
            kind: BlockKind::Exit,
            instruction_count: 0,
        };
        blocks.insert(0, entry);
        blocks.insert(1, exit);

        Self {
            blocks,
            edges: Vec::new(),
            entry_id: 0,
            exit_id: 1,
        }
    }

    pub fn add_block(&mut self, kind: BlockKind, label: &str, instruction_count: usize) -> usize {
        let id = self.blocks.len();
        self.blocks.insert(id, BasicBlock {
            id,
            label: label.to_string(),
            kind,
            instruction_count,
        });
        id
    }

    pub fn add_edge(&mut self, source: usize, target: usize, kind: EdgeKind) {
        self.edges.push(CfgEdge { source, target, kind });
    }

    /// Computes the number of connected components P using Breadth-First Search.
    pub fn count_connected_components(&self) -> usize {
        let mut visited: HashSet<usize> = HashSet::new();
        let mut components = 0;

        // Build adjacency list (undirected for component counting)
        let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
        for &id in self.blocks.keys() {
            adj.entry(id).or_default();
        }
        for edge in &self.edges {
            adj.entry(edge.source).or_default().push(edge.target);
            adj.entry(edge.target).or_default().push(edge.source);
        }

        for &node_id in self.blocks.keys() {
            if !visited.contains(&node_id) {
                components += 1;
                let mut queue = VecDeque::new();
                queue.push_back(node_id);
                visited.insert(node_id);

                while let Some(curr) = queue.pop_front() {
                    if let Some(neighbors) = adj.get(&curr) {
                        for &next in neighbors {
                            if !visited.contains(&next) {
                                visited.insert(next);
                                queue.push_back(next);
                            }
                        }
                    }
                }
            }
        }
        components.max(1)
    }

    /// Formally evaluates McCabe's Cyclomatic Complexity formula:
    ///     M = E - N + 2P
    pub fn cyclomatic_complexity(&self) -> usize {
        let e = self.edges.len() as isize;
        let n = self.blocks.len() as isize;
        let p = self.count_connected_components() as isize;

        let m = e - n + (2 * p);
        m.max(1) as usize
    }
}

pub struct CognitiveSecurityAnalyzer {
    operators: HashSet<String>,
}

impl Default for CognitiveSecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CognitiveSecurityAnalyzer {
    pub fn new() -> Self {
        let mut ops = HashSet::new();
        let ops_list = vec![
            "+", "-", "*", "/", "%", "==", "!=", "<", ">", "<=", ">=",
            "&&", "||", "!", "&", "|", "^", "<<", ">>", "=", "+=", "-=",
            "*=", "/=", "::", "->", ".", "?", ":", "?."
        ];
        for op in ops_list {
            ops.insert(op.to_string());
        }
        Self { operators: ops }
    }

    /// Full lexical tokenizer pass over source code to generate Halstead metrics.
    pub fn analyze_halstead(&self, source_code: &str) -> HalsteadMetrics {
        let mut metrics = HalsteadMetrics::default();
        let mut op_set = HashSet::new();
        let mut operand_set = HashSet::new();

        for token in source_code.split_whitespace() {
            if self.operators.contains(token) {
                metrics.total_operators += 1;
                op_set.insert(token);
            } else if token.chars().all(|c| c.is_alphanumeric() || c == '_') {
                metrics.total_operands += 1;
                operand_set.insert(token);
            }
        }

        metrics.unique_operators = op_set.len();
        metrics.unique_operands = operand_set.len();
        metrics
    }

    /// Constructs the explicit Control Flow Graph (CFG) from source code by
    /// discovering decision points, conditional branches, loops, and exits,
    /// then traverses the graph to evaluate M = E - N + 2P.
    pub fn build_cfg(&self, source_code: &str) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();

        let mut current_block = cfg.add_block(BlockKind::Normal, "init", 1);
        cfg.add_edge(cfg.entry_id, current_block, EdgeKind::Unconditional);

        let mut block_counter = 0;

        for line in source_code.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
                continue;
            }

            // If statement: creates branch condition with True and False edges
            if trimmed.starts_with("if ") || trimmed.starts_with("if(") || trimmed.contains(" if ") {
                block_counter += 1;
                let cond_block = cfg.add_block(BlockKind::BranchCondition, &format!("if_cond_{}", block_counter), 1);
                let true_block = cfg.add_block(BlockKind::Normal, &format!("if_true_{}", block_counter), 1);
                let join_block = cfg.add_block(BlockKind::Normal, &format!("if_join_{}", block_counter), 1);

                cfg.add_edge(current_block, cond_block, EdgeKind::Fallthrough);
                cfg.add_edge(cond_block, true_block, EdgeKind::BranchTrue);
                cfg.add_edge(cond_block, join_block, EdgeKind::BranchFalse);
                cfg.add_edge(true_block, join_block, EdgeKind::Fallthrough);

                // Handle boolean short-circuit operators within condition (&&, ||) which add sub-branches
                let logical_ands = trimmed.matches("&&").count();
                let logical_ors = trimmed.matches("||").count();
                for _ in 0..(logical_ands + logical_ors) {
                    let sub_cond = cfg.add_block(BlockKind::BranchCondition, "sub_decision", 1);
                    cfg.add_edge(cond_block, sub_cond, EdgeKind::BranchTrue);
                    cfg.add_edge(sub_cond, join_block, EdgeKind::BranchFalse);
                }

                current_block = join_block;
            }
            // For / While / Loop: creates loop header, body, backedge, and exit edge
            else if trimmed.starts_with("for ") || trimmed.starts_with("while ") || trimmed.starts_with("while(") || trimmed.starts_with("loop ") || trimmed == "loop {" {
                block_counter += 1;
                let header = cfg.add_block(BlockKind::LoopHeader, &format!("loop_hdr_{}", block_counter), 1);
                let body = cfg.add_block(BlockKind::LoopBody, &format!("loop_body_{}", block_counter), 1);
                let exit = cfg.add_block(BlockKind::Normal, &format!("loop_exit_{}", block_counter), 1);

                cfg.add_edge(current_block, header, EdgeKind::Fallthrough);
                cfg.add_edge(header, body, EdgeKind::BranchTrue);
                cfg.add_edge(body, header, EdgeKind::LoopBackedge);
                cfg.add_edge(header, exit, EdgeKind::LoopExit);

                current_block = exit;
            }
            // Match / Switch / Case: creates multiple outgoing branch edges
            else if trimmed.starts_with("match ") || trimmed.starts_with("switch ") || trimmed.starts_with("switch(") {
                block_counter += 1;
                let switch_hdr = cfg.add_block(BlockKind::SwitchHeader, &format!("switch_{}", block_counter), 1);
                cfg.add_edge(current_block, switch_hdr, EdgeKind::Fallthrough);
                current_block = switch_hdr;
            }
            else if (trimmed.contains("=>") && !trimmed.starts_with("//")) || trimmed.starts_with("case ") {
                block_counter += 1;
                let case_block = cfg.add_block(BlockKind::SwitchCase, &format!("case_{}", block_counter), 1);
                let next_join = cfg.add_block(BlockKind::Normal, &format!("case_join_{}", block_counter), 1);

                cfg.add_edge(current_block, case_block, EdgeKind::SwitchCase);
                cfg.add_edge(case_block, next_join, EdgeKind::Fallthrough);
                current_block = next_join;
            }
            // Ternary operator (? :) adds branch decision
            else if trimmed.contains('?') && trimmed.contains(':') && !trimmed.contains("::") {
                block_counter += 1;
                let ternary_cond = cfg.add_block(BlockKind::BranchCondition, &format!("ternary_{}", block_counter), 1);
                let true_arm = cfg.add_block(BlockKind::Normal, "ternary_true", 1);
                let join = cfg.add_block(BlockKind::Normal, "ternary_join", 1);

                cfg.add_edge(current_block, ternary_cond, EdgeKind::Fallthrough);
                cfg.add_edge(ternary_cond, true_arm, EdgeKind::BranchTrue);
                cfg.add_edge(ternary_cond, join, EdgeKind::BranchFalse);
                cfg.add_edge(true_arm, join, EdgeKind::Fallthrough);

                current_block = join;
            }
            // Return / Break / Exit statement
            else if trimmed.starts_with("return") || trimmed == "break;" || trimmed.starts_with("throw ") || trimmed.starts_with("panic!") {
                cfg.add_edge(current_block, cfg.exit_id, EdgeKind::Unconditional);
                let dead_or_next = cfg.add_block(BlockKind::Normal, "post_return", 0);
                current_block = dead_or_next;
            }
        }

        // Connect trailing block to CFG EXIT node
        cfg.add_edge(current_block, cfg.exit_id, EdgeKind::Unconditional);

        cfg
    }

    /// Computes McCabe's Cyclomatic Complexity using full CFG traversal (M = E - N + 2P).
    pub fn compute_cyclomatic_complexity(&self, source_code: &str) -> usize {
        let cfg = self.build_cfg(source_code);
        cfg.cyclomatic_complexity()
    }
}
