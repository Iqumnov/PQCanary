use std::collections::{HashMap, HashSet};

/// SMT-LIB2 variable sorts (types)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtSort {
    BitVec(u32),       // (_ BitVec N) — N-bit bitvector
    Bool,              // Boolean sort
    Array(u32, u32),   // (Array (_ BitVec addr_bits) (_ BitVec val_bits))
}

impl SmtSort {
    pub fn to_smtlib2(&self) -> String {
        match self {
            SmtSort::BitVec(n) => format!("(_ BitVec {})", n),
            SmtSort::Bool => "Bool".to_string(),
            SmtSort::Array(idx, val) => format!("(Array (_ BitVec {}) (_ BitVec {}))", idx, val),
        }
    }
}

/// An SMT expression node. Forms a tree for complex nested constraints.
#[derive(Debug, Clone)]
pub enum SmtExpr {
    // Atoms
    Var(String),
    BitVecLit(i64, u32),   // value, bit-width
    BoolLit(bool),

    // Bitvector arithmetic
    BvAdd(Box<SmtExpr>, Box<SmtExpr>),
    BvSub(Box<SmtExpr>, Box<SmtExpr>),
    BvMul(Box<SmtExpr>, Box<SmtExpr>),
    BvUDiv(Box<SmtExpr>, Box<SmtExpr>),
    BvURem(Box<SmtExpr>, Box<SmtExpr>),

    // Bitvector bitwise
    BvAnd(Box<SmtExpr>, Box<SmtExpr>),
    BvOr(Box<SmtExpr>, Box<SmtExpr>),
    BvXor(Box<SmtExpr>, Box<SmtExpr>),
    BvNot(Box<SmtExpr>),
    BvShl(Box<SmtExpr>, Box<SmtExpr>),
    BvLShr(Box<SmtExpr>, Box<SmtExpr>),  // Logical right shift

    // Bitvector comparisons (produce Bool)
    BvULt(Box<SmtExpr>, Box<SmtExpr>),
    BvULe(Box<SmtExpr>, Box<SmtExpr>),
    BvUGt(Box<SmtExpr>, Box<SmtExpr>),
    BvUGe(Box<SmtExpr>, Box<SmtExpr>),
    BvSLt(Box<SmtExpr>, Box<SmtExpr>),   // Signed less-than
    BvSGe(Box<SmtExpr>, Box<SmtExpr>),   // Signed greater-eq
    Eq(Box<SmtExpr>, Box<SmtExpr>),
    Neq(Box<SmtExpr>, Box<SmtExpr>),

    // Boolean logic
    And(Box<SmtExpr>, Box<SmtExpr>),
    Or(Box<SmtExpr>, Box<SmtExpr>),
    Not(Box<SmtExpr>),
    Implies(Box<SmtExpr>, Box<SmtExpr>),
    Ite(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>),  // if-then-else

    // Bitvector extension / slicing
    ZeroExtend(u32, Box<SmtExpr>),    // zero_extend by N bits
    SignExtend(u32, Box<SmtExpr>),    // sign_extend by N bits
    Extract(u32, u32, Box<SmtExpr>), // extract[hi:lo]
    Concat(Box<SmtExpr>, Box<SmtExpr>),

    // Array theory
    ArraySelect(Box<SmtExpr>, Box<SmtExpr>),               // (select arr idx)
    ArrayStore(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>),  // (store arr idx val)
}

impl SmtExpr {
    /// Recursively converts the expression tree to an SMT-LIB2 string.
    pub fn to_smtlib2(&self) -> String {
        match self {
            SmtExpr::Var(name) => name.clone(),
            SmtExpr::BitVecLit(v, w) => {
                if *v >= 0 {
                    format!("(_ bv{} {})", v, w)
                } else {
                    // Represent negative as two's complement bvN
                    let mask: i64 = if *w >= 64 {
                        -1i64
                    } else {
                        (1i64 << *w).wrapping_sub(1)
                    };
                    let twos = (*v) & mask;
                    format!("(_ bv{} {})", twos as u64, w)
                }
            }
            SmtExpr::BoolLit(b) => if *b { "true".to_string() } else { "false".to_string() },

            SmtExpr::BvAdd(a, b)  => format!("(bvadd {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvSub(a, b)  => format!("(bvsub {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvMul(a, b)  => format!("(bvmul {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUDiv(a, b) => format!("(bvudiv {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvURem(a, b) => format!("(bvurem {} {})", a.to_smtlib2(), b.to_smtlib2()),

            SmtExpr::BvAnd(a, b)  => format!("(bvand {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvOr(a, b)   => format!("(bvor {} {})",  a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvXor(a, b)  => format!("(bvxor {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvNot(a)     => format!("(bvnot {})", a.to_smtlib2()),
            SmtExpr::BvShl(a, b)  => format!("(bvshl {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvLShr(a, b) => format!("(bvlshr {} {})", a.to_smtlib2(), b.to_smtlib2()),

            SmtExpr::BvULt(a, b)  => format!("(bvult {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvULe(a, b)  => format!("(bvule {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUGt(a, b)  => format!("(bvugt {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUGe(a, b)  => format!("(bvuge {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvSLt(a, b)  => format!("(bvslt {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvSGe(a, b)  => format!("(bvsge {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Eq(a, b)     => format!("(= {} {})",     a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Neq(a, b)    => format!("(not (= {} {}))", a.to_smtlib2(), b.to_smtlib2()),

            SmtExpr::And(a, b)     => format!("(and {} {})",     a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Or(a, b)      => format!("(or {} {})",      a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Not(a)        => format!("(not {})",         a.to_smtlib2()),
            SmtExpr::Implies(a, b) => format!("(=> {} {})",       a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Ite(c, t, e)  => format!("(ite {} {} {})",  c.to_smtlib2(), t.to_smtlib2(), e.to_smtlib2()),

            SmtExpr::ZeroExtend(n, a) => format!("((_ zero_extend {}) {})", n, a.to_smtlib2()),
            SmtExpr::SignExtend(n, a)  => format!("((_ sign_extend {}) {})", n, a.to_smtlib2()),
            SmtExpr::Extract(hi, lo, a) => format!("((_ extract {} {}) {})", hi, lo, a.to_smtlib2()),
            SmtExpr::Concat(a, b)      => format!("(concat {} {})", a.to_smtlib2(), b.to_smtlib2()),

            SmtExpr::ArraySelect(arr, idx) => format!("(select {} {})", arr.to_smtlib2(), idx.to_smtlib2()),
            SmtExpr::ArrayStore(arr, idx, val) => format!("(store {} {} {})", arr.to_smtlib2(), idx.to_smtlib2(), val.to_smtlib2()),
        }
    }
}

/// Taint tracking: which variables are derived from symbolic (attacker-controlled) inputs.
#[derive(Debug, Clone)]
pub struct TaintTracker {
    pub tainted: HashSet<String>,
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintTracker {
    pub fn new() -> Self { Self { tainted: HashSet::new() } }

    /// Mark a variable as tainted (derived from external symbolic input)
    pub fn taint(&mut self, var: &str) { self.tainted.insert(var.to_string()); }

    /// Propagate taint: if either input is tainted, the output is also tainted
    pub fn propagate_binary(&mut self, lhs: &str, rhs: &str, result: &str) {
        if self.tainted.contains(lhs) || self.tainted.contains(rhs) {
            self.tainted.insert(result.to_string());
        }
    }

    /// Check if a variable is tainted
    pub fn is_tainted(&self, var: &str) -> bool { self.tainted.contains(var) }
}

/// The full production SMT constraint accumulator.
/// Manages the symbol table, array theory for memory, and taint propagation.
#[derive(Debug, Clone)]
pub struct SmtConstraintTree {
    // Ordered variable declarations (declare-const)
    declarations: Vec<(String, SmtSort)>,
    declared_set: HashSet<String>,

    // Ordered assertions
    assertions: Vec<SmtExpr>,

    // Memory array symbol (models full process memory as an SMT array)
    pub memory_array: String,

    // Taint tracker
    pub taint: TaintTracker,

    // Named intermediate results for re-use and readability
    pub named_exprs: HashMap<String, SmtExpr>,
}

impl Default for SmtConstraintTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtConstraintTree {
    pub fn new() -> Self {
        let mut tree = Self {
            declarations: Vec::new(),
            declared_set: HashSet::new(),
            assertions: Vec::new(),
            memory_array: "MEM".to_string(),
            taint: TaintTracker::new(),
            named_exprs: HashMap::new(),
        };
        // Declare the global memory array: (Array (_ BitVec 64) (_ BitVec 8))
        // Maps 64-bit virtual addresses to 8-bit bytes — models the entire process address space.
        tree.declarations.push(("MEM".to_string(), SmtSort::Array(64, 8)));
        tree.declared_set.insert("MEM".to_string());
        tree
    }

    /// Declares a symbolic N-bit bitvector variable (attacker-controlled input byte)
    pub fn declare_symbolic_bitvec(&mut self, name: &str, bits: u32) -> SmtExpr {
        if !self.declared_set.contains(name) {
            self.declarations.push((name.to_string(), SmtSort::BitVec(bits)));
            self.declared_set.insert(name.to_string());
            self.taint.taint(name);
        }
        SmtExpr::Var(name.to_string())
    }

    /// Declares a symbolic 8-bit byte (one byte of attacker-controlled input)
    pub fn declare_symbolic_byte(&mut self, name: &str) -> SmtExpr {
        self.declare_symbolic_bitvec(name, 8)
    }

    /// Declares a symbolic 64-bit pointer (e.g., attacker-controlled buffer index)
    pub fn declare_symbolic_ptr(&mut self, name: &str) -> SmtExpr {
        self.declare_symbolic_bitvec(name, 64)
    }

    /// Assert that a symbolic byte value is bounded to the valid ASCII printable range.
    /// Adds: (assert (and (bvuge sym #x20) (bvule sym #x7e)))
    pub fn constrain_ascii_printable(&mut self, var_expr: &SmtExpr) {
        let lower = SmtExpr::BitVecLit(0x20, 8);
        let upper = SmtExpr::BitVecLit(0x7e, 8);
        let ge = SmtExpr::BvUGe(Box::new(var_expr.clone()), Box::new(lower));
        let le = SmtExpr::BvULe(Box::new(var_expr.clone()), Box::new(upper));
        self.assertions.push(SmtExpr::And(Box::new(ge), Box::new(le)));
    }

    /// Assert that a memory read at a given symbolic address does not exceed the known
    /// buffer bound (buf_base + buf_size). Proves buffer overflow exploitability.
    /// If SAT: the constraints are satisfiable → overflow IS reachable.
    pub fn assert_bounds_check_violation(
        &mut self,
        symbolic_index: &SmtExpr,
        buf_base: i64,
        buf_size: i64,
    ) {
        self.assert_bounds_check_violation_with_bits(symbolic_index, 8, buf_base, buf_size);
    }

    /// Assert that a memory read at a given symbolic address exceeds the known
    /// buffer bound (buf_base + buf_size). Supports flexible index bitwidths (8, 16, 32, 64-bit)
    /// to avoid SMT sort mismatches.
    pub fn assert_bounds_check_violation_with_bits(
        &mut self,
        symbolic_index: &SmtExpr,
        index_bits: u32,
        buf_base: i64,
        buf_size: i64,
    ) {
        let upper_bound = SmtExpr::BitVecLit(buf_base + buf_size, 64);
        let wide_idx = if index_bits < 64 {
            SmtExpr::ZeroExtend(64 - index_bits, Box::new(symbolic_index.clone()))
        } else if index_bits == 64 {
            symbolic_index.clone()
        } else {
            SmtExpr::Extract(63, 0, Box::new(symbolic_index.clone()))
        };
        let oob = SmtExpr::BvUGe(Box::new(wide_idx), Box::new(upper_bound));
        self.assertions.push(oob);
    }

    /// Assert that a symbolic index can equal a target secret index
    /// (e.g., proving a timing side-channel leaks the secret array position).
    pub fn assert_secret_index_reachable(&mut self, symbolic_index: &SmtExpr, secret_offset: i64, bits: u32) {
        let secret = SmtExpr::BitVecLit(secret_offset, bits);
        let eq = SmtExpr::Eq(Box::new(symbolic_index.clone()), Box::new(secret));
        self.assertions.push(eq);
    }

    /// Models an AES S-Box lookup symbolically:
    /// Declares the 256-entry S-Box as an SMT array constant and asserts the lookup relationship.
    /// This is the foundational step for symbolic DFA beyond a single byte.
    pub fn model_aes_sbox_lookup(&mut self, input_var: &str, output_var: &str, sbox_values: &[u8; 256]) {
        // Build a chain of ite (if-then-else) expressions modelling the full 256-entry LUT
        let mut sbox_expr: SmtExpr = SmtExpr::BitVecLit(sbox_values[255] as i64, 8);

        for idx in (0..255usize).rev() {
            let key = SmtExpr::BitVecLit(idx as i64, 8);
            let val = SmtExpr::BitVecLit(sbox_values[idx] as i64, 8);
            let cond = SmtExpr::Eq(Box::new(SmtExpr::Var(input_var.to_string())), Box::new(key));
            sbox_expr = SmtExpr::Ite(Box::new(cond), Box::new(val), Box::new(sbox_expr));
        }

        // Declare the output variable and assert it equals the s-box LUT result
        if !self.declared_set.contains(output_var) {
            self.declarations.push((output_var.to_string(), SmtSort::BitVec(8)));
            self.declared_set.insert(output_var.to_string());
        }
        let eq = SmtExpr::Eq(
            Box::new(SmtExpr::Var(output_var.to_string())),
            Box::new(sbox_expr),
        );
        self.assertions.push(eq);
    }

    /// Adds a raw SMT expression as an assertion.
    pub fn add_raw_assertion(&mut self, expr: SmtExpr) {
        self.assertions.push(expr);
    }

    /// Compiles the entire constraint tree into a complete, valid SMT-LIB2 script.
    pub fn compile_to_smtlib2(&self) -> String {
        let mut script = String::with_capacity(4096);
        script.push_str(";; PQCanary Concolic Constraint Payload — QF_ABVFP Logic\n");
        script.push_str("(set-logic QF_ABV)\n"); // Quantifier-Free Array + Bit-Vector theory
        script.push_str("(set-option :produce-models true)\n");

        // Declare all symbolic variables and arrays
        for (name, sort) in &self.declarations {
            script.push_str(&format!("(declare-const {} {})\n", name, sort.to_smtlib2()));
        }

        script.push('\n');

        // Emit all constraints as top-level assertions
        for assertion in &self.assertions {
            script.push_str(&format!("(assert {})\n", assertion.to_smtlib2()));
        }

        script.push('\n');
        // The caller appends (check-sat) and (get-model) after this
        script
    }

    /// Returns the count of symbolic variables declared (proxy for analysis complexity)
    pub fn symbolic_variable_count(&self) -> usize {
        self.taint.tainted.len()
    }

    /// Returns the count of assertions (proxy for path constraint depth)
    pub fn constraint_depth(&self) -> usize {
        self.assertions.len()
    }
}
