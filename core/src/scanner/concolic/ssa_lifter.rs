use std::collections::HashMap;
use tree_sitter::Node;

/// Static Single Assignment (SSA) IR Instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum SsaInstruction {
    // Arithmetic
    Add(String, String, String),
    Sub(String, String, String),
    Mul(String, String, String),
    Div(String, String, String),
    Mod(String, String, String),

    // Bitwise
    Shl(String, String, String),
    Shr(String, String, String),
    BitAnd(String, String, String),
    BitOr(String, String, String),
    BitXor(String, String, String),

    // Memory operations
    Load(String, String),   // Target variable, source pointer/offset variable
    Store(String, String),  // Target pointer/offset variable, source variable
    Alloc(String, usize),   // Allocates a symbolic block of size

    // Assignments and Literals
    Assign(String, String),      // Target variable, source variable
    AssignLiteral(String, i64),  // Target variable, concrete integer

    // Control Flow
    Phi(String, Vec<String>),             // Target variable, list of source variables from branches
    Branch(String, String, String),       // Condition variable, True label, False label
    Label(String),                        // Control flow block label
    Jump(String),                         // Unconditional jump to label

    // Verification Assertions (Bound Checks)
    AssertLess(String, String),
    AssertGreaterEq(String, String),

    // Comparisons & Boolean Logic
    Lt(String, String, String),
    Le(String, String, String),
    Gt(String, String, String),
    Ge(String, String, String),
    Eq(String, String, String),
    Ne(String, String, String),
    LogicalAnd(String, String, String),
    LogicalOr(String, String, String),
}

/// Lexical scope block tracker for resolving variable names to their active SSA versions.
#[derive(Debug, Clone)]
pub struct Scope {
    pub bindings: HashMap<String, String>, // original_name -> active_ssa_name
}

/// The Engine that translates a raw Tree-Sitter AST into an exhaustive SSA format.
pub struct SsaLifter {
    // Tracks the count of variable versions globally (e.g., "x" -> 3 for "x_3")
    variable_version_counters: HashMap<String, u32>,
    // Stack of active lexical scopes
    scope_stack: Vec<Scope>,
    // List of generated instructions
    pub instructions: Vec<SsaInstruction>,
    // Label counters for control flow blocks
    label_counter: u32,
    // Temporary variable counter
    temp_counter: u32,
}

impl Default for SsaLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl SsaLifter {
    pub fn new() -> Self {
        Self {
            variable_version_counters: HashMap::new(),
            scope_stack: vec![Scope { bindings: HashMap::new() }],
            instructions: Vec::new(),
            label_counter: 0,
            temp_counter: 0,
        }
    }

    /// Generates a fresh temporary variable name
    fn fresh_temp(&mut self) -> String {
        self.temp_counter += 1;
        format!("t_{}", self.temp_counter)
    }

    /// Generates a fresh control flow label name
    fn fresh_label(&mut self, prefix: &str) -> String {
        self.label_counter += 1;
        format!("label_{}_{}", prefix, self.label_counter)
    }

    /// Pushes a new lexical scope
    fn push_scope(&mut self) {
        self.scope_stack.push(Scope { bindings: HashMap::new() });
    }

    /// Pops the active lexical scope
    fn pop_scope(&mut self) {
        if self.scope_stack.len() > 1 {
            self.scope_stack.pop();
        }
    }

    /// Resolves the currently active SSA name for a given variable
    pub fn resolve_variable(&self, name: &str) -> String {
        for scope in self.scope_stack.iter().rev() {
            if let Some(ssa_name) = scope.bindings.get(name) {
                return ssa_name.clone();
            }
        }
        // Fallback for global or undeclared variables
        format!("{}_0", name)
    }

    /// Generates a new SSA version of a variable and binds it in the active scope
    pub fn define_variable(&mut self, name: &str) -> String {
        let counter = self.variable_version_counters.entry(name.to_string()).or_insert(0);
        *counter += 1;
        let ssa_name = format!("{}_{}", name, counter);
        
        if let Some(active_scope) = self.scope_stack.last_mut() {
            active_scope.bindings.insert(name.to_string(), ssa_name.clone());
        }
        ssa_name
    }

    /// Retrieves node text from source code
    fn get_node_text<'a>(&self, node: Node<'a>, source: &'a str) -> &'a str {
        &source[node.start_byte()..node.end_byte()]
    }

    /// Recursively walks the Tree-Sitter AST and lifts it to SSA instructions
    pub fn lift_ast(&mut self, root_node: Node, source: &str) -> Result<(), &'static str> {
        let node_kind = root_node.kind();
        
        match node_kind {
            "program" | "statement_block" => {
                self.push_scope();
                let mut cursor = root_node.walk();
                for child in root_node.children(&mut cursor) {
                    self.lift_ast(child, source)?;
                }
                self.pop_scope();
            }
            "variable_declaration" => {
                let mut cursor = root_node.walk();
                for child in root_node.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        self.lift_ast(child, source)?;
                    }
                }
            }
            "variable_declarator" => {
                let name_node = root_node.child_by_field_name("name").ok_or("Missing variable name")?;
                let value_node = root_node.child_by_field_name("value");
                let name_str = self.get_node_text(name_node, source);

                let ssa_target = self.define_variable(name_str);

                if let Some(val_node) = value_node {
                    let val_var = self.lift_expression(val_node, source)?;
                    self.instructions.push(SsaInstruction::Assign(ssa_target, val_var));
                } else {
                    // Default uninitialized
                    self.instructions.push(SsaInstruction::AssignLiteral(ssa_target, 0));
                }
            }
            "expression_statement" => {
                if let Some(child) = root_node.child(0) {
                    self.lift_expression(child, source)?;
                }
            }
            "if_statement" => {
                let condition_node = root_node.child_by_field_name("condition").ok_or("Missing if condition")?;
                let consequence_node = root_node.child_by_field_name("consequence").ok_or("Missing if consequence block")?;
                let alternative_node = root_node.child_by_field_name("alternative");

                let cond_var = self.lift_expression(condition_node, source)?;

                let label_true = self.fresh_label("true");
                let label_false = self.fresh_label("false");
                let label_end = self.fresh_label("end");

                let actual_label_false = if alternative_node.is_some() {
                    label_false.clone()
                } else {
                    label_end.clone()
                };

                self.instructions.push(SsaInstruction::Branch(cond_var, label_true.clone(), actual_label_false.clone()));

                // Consequence block
                self.instructions.push(SsaInstruction::Label(label_true));
                self.lift_ast(consequence_node, source)?;
                self.instructions.push(SsaInstruction::Jump(label_end.clone()));

                // Alternative block if exists
                if let Some(alt_node) = alternative_node {
                    self.instructions.push(SsaInstruction::Label(label_false));
                    self.lift_ast(alt_node, source)?;
                    self.instructions.push(SsaInstruction::Jump(label_end.clone()));
                }

                self.instructions.push(SsaInstruction::Label(label_end));
            }
            "for_statement" | "while_statement" => {
                // Loop unrolling or basic loop structure representation
                let label_loop_head = self.fresh_label("loop_head");
                let label_loop_body = self.fresh_label("loop_body");
                let label_loop_end = self.fresh_label("loop_end");

                self.instructions.push(SsaInstruction::Jump(label_loop_head.clone()));
                self.instructions.push(SsaInstruction::Label(label_loop_head.clone()));

                // Handle condition
                let cond_var = if node_kind == "while_statement" {
                    let condition_node = root_node.child_by_field_name("condition").ok_or("Missing loop condition")?;
                    self.lift_expression(condition_node, source)?
                } else {
                    // Simulating a bounded or true condition for standard static loops
                    let cond_name = self.fresh_temp();
                    self.instructions.push(SsaInstruction::AssignLiteral(cond_name.clone(), 1));
                    cond_name
                };

                self.instructions.push(SsaInstruction::Branch(cond_var, label_loop_body.clone(), label_loop_end.clone()));

                self.instructions.push(SsaInstruction::Label(label_loop_body));
                let body_node = root_node.child_by_field_name("body").ok_or("Missing loop body")?;
                self.lift_ast(body_node, source)?;
                self.instructions.push(SsaInstruction::Jump(label_loop_head));

                self.instructions.push(SsaInstruction::Label(label_loop_end));
            }
            _ => {
                // Leaf/Unknown nodes - walk children recursively
                let mut cursor = root_node.walk();
                for child in root_node.children(&mut cursor) {
                    self.lift_ast(child, source)?;
                }
            }
        }
        Ok(())
    }

    /// Evaluates an AST expression and registers intermediate SSA variables
    pub fn lift_expression(&mut self, node: Node, source: &str) -> Result<String, &'static str> {
        let kind = node.kind();
        
        match kind {
            "number" | "integer" | "float" => {
                let number_str = self.get_node_text(node, source);
                let value = parse_numeric_literal(number_str)?;
                let temp = self.fresh_temp();
                self.instructions.push(SsaInstruction::AssignLiteral(temp.clone(), value));
                Ok(temp)
            }
            "true" | "false" => {
                let val = if node.kind() == "true" { 1 } else { 0 };
                let temp = self.fresh_temp();
                self.instructions.push(SsaInstruction::AssignLiteral(temp.clone(), val));
                Ok(temp)
            }
            "boolean" => {
                let text = self.get_node_text(node, source);
                let val = if text == "true" { 1 } else { 0 };
                let temp = self.fresh_temp();
                self.instructions.push(SsaInstruction::AssignLiteral(temp.clone(), val));
                Ok(temp)
            }
            "identifier" => {
                let name = self.get_node_text(node, source);
                Ok(self.resolve_variable(name))
            }
            "binary_expression" => {
                let left_node = node.child_by_field_name("left").ok_or("Missing left child")?;
                let right_node = node.child_by_field_name("right").ok_or("Missing right child")?;
                let operator_node = node.child(1).ok_or("Missing operator")?;
                let operator = self.get_node_text(operator_node, source);

                let left_var = self.lift_expression(left_node, source)?;
                let right_var = self.lift_expression(right_node, source)?;
                let temp_res = self.fresh_temp();

                let instr = match operator {
                    "+" => SsaInstruction::Add(temp_res.clone(), left_var, right_var),
                    "-" => SsaInstruction::Sub(temp_res.clone(), left_var, right_var),
                    "*" => SsaInstruction::Mul(temp_res.clone(), left_var, right_var),
                    "/" => SsaInstruction::Div(temp_res.clone(), left_var, right_var),
                    "%" => SsaInstruction::Mod(temp_res.clone(), left_var, right_var),
                    "<<" => SsaInstruction::Shl(temp_res.clone(), left_var, right_var),
                    ">>" => SsaInstruction::Shr(temp_res.clone(), left_var, right_var),
                    "&" => SsaInstruction::BitAnd(temp_res.clone(), left_var, right_var),
                    "|" => SsaInstruction::BitOr(temp_res.clone(), left_var, right_var),
                    "^" => SsaInstruction::BitXor(temp_res.clone(), left_var, right_var),
                    "<" => SsaInstruction::Lt(temp_res.clone(), left_var, right_var),
                    "<=" => SsaInstruction::Le(temp_res.clone(), left_var, right_var),
                    ">" => SsaInstruction::Gt(temp_res.clone(), left_var, right_var),
                    ">=" => SsaInstruction::Ge(temp_res.clone(), left_var, right_var),
                    "==" | "===" => SsaInstruction::Eq(temp_res.clone(), left_var, right_var),
                    "!=" | "!==" => SsaInstruction::Ne(temp_res.clone(), left_var, right_var),
                    "&&" => SsaInstruction::LogicalAnd(temp_res.clone(), left_var, right_var),
                    "||" => SsaInstruction::LogicalOr(temp_res.clone(), left_var, right_var),
                    _ => return Err("Unsupported binary operator encountered"),
                };

                self.instructions.push(instr);
                Ok(temp_res)
            }
            "assignment_expression" => {
                let left_node = node.child_by_field_name("left").ok_or("Missing left assignee")?;
                let right_node = node.child_by_field_name("right").ok_or("Missing right value")?;
                
                let right_var = self.lift_expression(right_node, source)?;

                if left_node.kind() == "identifier" {
                    let name_str = self.get_node_text(left_node, source);
                    let new_ssa = self.define_variable(name_str);
                    self.instructions.push(SsaInstruction::Assign(new_ssa.clone(), right_var));
                    Ok(new_ssa)
                } else if left_node.kind() == "subscript_expression" {
                    // Array element write operation arr[index] = val
                    let array_node = left_node.child_by_field_name("object").ok_or("Missing array base object")?;
                    let index_node = left_node.child_by_field_name("index").ok_or("Missing array index node")?;

                    let array_var = self.lift_expression(array_node, source)?;
                    let _index_var = self.lift_expression(index_node, source)?;

                    self.instructions.push(SsaInstruction::Store(array_var.clone(), right_var.clone()));
                    Ok(right_var)
                } else {
                    Err("Unsupported LHS assignee pattern")
                }
            }
            "subscript_expression" => {
                let array_node = node.child_by_field_name("object").ok_or("Missing array base object")?;
                let index_node = node.child_by_field_name("index").ok_or("Missing array index node")?;

                let array_var = self.lift_expression(array_node, source)?;
                let index_var = self.lift_expression(index_node, source)?;
                
                // Construct implicit safety checks for memory bounds analysis
                let array_len_var = format!("{}_len", array_var);
                self.instructions.push(SsaInstruction::AssertGreaterEq(index_var.clone(), "0_const".to_string()));
                self.instructions.push(SsaInstruction::AssertLess(index_var.clone(), array_len_var));

                let target_temp = self.fresh_temp();
                self.instructions.push(SsaInstruction::Load(target_temp.clone(), array_var));
                Ok(target_temp)
            }
            _ => {
                // If it is an unmapped expression node type, try to resolve children
                let mut cursor = node.walk();
                let mut last_var = String::new();
                for child in node.children(&mut cursor) {
                    last_var = self.lift_expression(child, source)?;
                }
                if last_var.is_empty() {
                    let default_temp = self.fresh_temp();
                    self.instructions.push(SsaInstruction::AssignLiteral(default_temp.clone(), 0));
                    Ok(default_temp)
                } else {
                    Ok(last_var)
                }
            }
        }
    }
}

/// Robust numeric literal parser supporting hexadecimal, binary, octal, underscores, and suffixes.
pub(crate) fn parse_numeric_literal(s: &str) -> Result<i64, &'static str> {
    let clean = s.trim().replace('_', "");
    let clean = clean.trim_end_matches(['u', 'U', 'l', 'L', 'i', 'I', 'z', 'Z']);
    if clean.is_empty() {
        return Err("Failed to parse numeric literal: empty");
    }
    if let Some(stripped) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
        i64::from_str_radix(stripped, 16)
            .or_else(|_| u64::from_str_radix(stripped, 16).map(|v| v as i64))
            .map_err(|_| "Failed to parse numeric literal: invalid hex")
    } else if let Some(stripped) = clean.strip_prefix("0b").or_else(|| clean.strip_prefix("0B")) {
        i64::from_str_radix(stripped, 2)
            .or_else(|_| u64::from_str_radix(stripped, 2).map(|v| v as i64))
            .map_err(|_| "Failed to parse numeric literal: invalid bin")
    } else if let Some(stripped) = clean.strip_prefix("0o").or_else(|| clean.strip_prefix("0O")) {
        i64::from_str_radix(stripped, 8)
            .or_else(|_| u64::from_str_radix(stripped, 8).map(|v| v as i64))
            .map_err(|_| "Failed to parse numeric literal: invalid oct")
    } else if clean.starts_with('0') && clean.len() > 1 && clean.chars().all(|c| ('0'..='7').contains(&c)) {
        i64::from_str_radix(&clean[1..], 8)
            .or_else(|_| clean.parse::<i64>())
            .map_err(|_| "Failed to parse numeric literal")
    } else {
        clean.parse::<i64>()
            .or_else(|_| clean.parse::<u64>().map(|v| v as i64))
            .or_else(|_| {
                let f = clean.parse::<f64>().map_err(|_| "Failed to parse numeric literal")?;
                if f.is_finite() {
                    Ok(f as i64)
                } else {
                    Err("Failed to parse numeric literal: non-finite float")
                }
            })
    }
}

