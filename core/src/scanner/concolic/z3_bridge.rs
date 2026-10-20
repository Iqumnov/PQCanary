use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The result of a single Z3 satisfiability check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Z3Result {
    /// Constraints are satisfiable — a witness (exploit input) exists.
    Sat(HashMap<String, String>),
    /// Constraints are unsatisfiable — the path is mathematically safe.
    Unsat,
    /// Z3 exceeded the per-query time budget.
    Timeout,
    /// Z3 returned an unexpected error.
    Unknown(String),
}

/// Performance statistics for a single solver query.
#[derive(Debug, Clone)]
pub struct SolverStats {
    pub query_duration_ms: u64,
    pub variable_count: usize,
    pub assertion_count: usize,
}

/// Long-running Z3 session over a persistent IPC pipe.
/// Rather than spawning a new process per query (expensive), we hold one instance
/// open and reset the scope between queries with (push)/(pop).
pub struct Z3SolverSession {
    process: Child,
    stdout_reader: BufReader<std::process::ChildStdout>,
    timeout: Duration,
}

impl Z3SolverSession {
    /// Spawn one Z3 daemon and hold the IPC pipe open for the lifetime of the scan session.
    /// `-in`       → interactive SMT-LIB2 mode (reads from stdin)
    /// `-t:5000`   → per-check-sat timeout in milliseconds (passed via scripting)
    pub fn new() -> Result<Self, String> {
        let mut process = Command::new("z3")
            .args(["-in", "-smt2", "-t:10000"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!(
                "Failed to spawn Z3 daemon: {}. Ensure 'z3' is installed and in PATH.", e
            ))?;

        let stdout = process.stdout.take()
            .ok_or_else(|| "Z3 IPC stdout pipe is broken".to_string())?;
        let stdout_reader = BufReader::new(stdout);

        Ok(Self {
            process,
            stdout_reader,
            timeout: Duration::from_secs(10),
        })
    }

    /// Set the per-query solver timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a complete SMT-LIB2 script to Z3 and collect the full response.
    ///
    /// The script MUST end with `(check-sat)` and optionally `(get-model)`.
    /// We use SMT-LIB2 `(push 1)` / `(pop 1)` to isolate query scope without
    /// restarting the process.
    pub fn query(&mut self, smt_script: &str) -> Result<Z3Result, String> {
        let start = Instant::now();

        let stdin = self.process.stdin.as_mut()
            .ok_or("Z3 IPC stdin pipe is broken")?;

        // Push a scope frame so declarations don't persist across queries,
        // and inject explicit solver timeout into SMT-LIB2 options to prevent hangs.
        let timeout_ms = self.timeout.as_millis();
        let full_script = format!(
            "(set-option :timeout {})\n(set-option :pp.single-line true)\n(push 1)\n{}\n(check-sat)\n(get-model)\n(pop 1)\n",
            timeout_ms,
            smt_script
        );

        stdin.write_all(full_script.as_bytes())
            .map_err(|e| format!("Failed to write to Z3 stdin: {}", e))?;
        stdin.flush()
            .map_err(|e| format!("Failed to flush Z3 stdin: {}", e))?;

        // Read the response from stdout.
        // Z3 emits: one line for check-sat ("sat", "unsat", "unknown"),
        // then potentially multiple lines for the model, terminated by the "(pop 1)" response.
        let mut sat_line = String::new();
        let mut attempts = 0;
        loop {
            sat_line.clear();
            let bytes = self.stdout_reader.read_line(&mut sat_line)
                .map_err(|e| format!("Failed to read Z3 check-sat response: {}", e))?;
            if bytes == 0 {
                return Ok(Z3Result::Unknown("Z3 process stdout closed unexpectedly (EOF)".to_string()));
            }
            attempts += 1;
            let trimmed = sat_line.trim();
            if trimmed.is_empty() || trimmed.starts_with("(:warning") || trimmed.starts_with("; ") {
                if attempts > 30 {
                    return Ok(Z3Result::Unknown("Z3 emitted excessive diagnostic warnings".to_string()));
                }
                continue;
            }
            break;
        }

        let elapsed = start.elapsed();
        if elapsed > self.timeout {
            return Ok(Z3Result::Timeout);
        }

        match sat_line.trim() {
            "sat" => {
                // Parse the model: read until we hit the closing ")" of the (model ...) block
                let model_vars = Z3SolverSession::read_model_from_reader(&mut self.stdout_reader)?;
                Ok(Z3Result::Sat(model_vars))
            }
            "unsat" => Ok(Z3Result::Unsat),
            "unknown" => Ok(Z3Result::Unknown("Z3 returned unknown (resource limits hit)".to_string())),
            other => Ok(Z3Result::Unknown(format!("Unexpected Z3 output: '{}'", other))),
        }
    }

    /// Reads and parses a Z3 `(model ...)` block from the persistent stdout reader.
    /// Returns a map of variable name → concrete value string.
    fn read_model_from_reader(reader: &mut BufReader<std::process::ChildStdout>) -> Result<HashMap<String, String>, String> {
        let mut model = HashMap::new();
        let mut buffer = String::new();
        let mut depth = 0i32;
        let mut started = false;
        let mut lines_read = 0;
        let mut line = String::new();

        loop {
            lines_read += 1;
            if lines_read > 5000 {
                break;
            }

            line.clear();
            let bytes = reader.read_line(&mut line)
                .map_err(|e| format!("Failed to read Z3 model: {}", e))?;
            if bytes == 0 {
                // EOF reached
                break;
            }

            if line.trim().is_empty() {
                continue;
            }

            // Track parenthesis depth to know when the model block ends
            for ch in line.chars() {
                match ch {
                    '(' => { depth += 1; started = true; }
                    ')' => { depth -= 1; }
                    _ => {}
                }
            }
            buffer.push_str(&line);

            if started && depth <= 0 {
                break;
            }
        }

        // Normalize multi-line `(define-fun ...)` blocks into single logical lines
        let mut normalized_definitions: Vec<String> = Vec::new();
        for line in buffer.lines() {
            let tr = line.trim();
            if tr.starts_with("(define-fun") {
                normalized_definitions.push(tr.to_string());
            } else if let Some(last) = normalized_definitions.last_mut() {
                last.push(' ');
                last.push_str(tr);
            }
        }

        // Parse `(define-fun VARNAME () SORT VALUE)` lines from the model block
        for def_line in normalized_definitions {
            let parts: Vec<&str> = def_line.split_whitespace().collect();
            if parts.len() >= 5 {
                let var_name = parts[1].to_string();
                // The value is the last token before the closing ")"
                let value = parts[parts.len() - 1].trim_end_matches(')').to_string();
                model.insert(var_name, value);
            }
        }

        Ok(model)
    }

    /// Evaluate a set of independent constraints in batch,
    /// using push/pop to avoid repeated process spawning overhead.
    pub fn batch_query(&mut self, scripts: Vec<String>) -> Vec<(usize, Z3Result)> {
        scripts.into_iter().enumerate().map(|(idx, script)| {
            let result = self.query(&script).unwrap_or(Z3Result::Unknown("IPC failure".to_string()));
            (idx, result)
        }).collect()
    }

    /// Gracefully terminate the Z3 daemon.
    pub fn shutdown(mut self) {
        if let Some(mut stdin) = self.process.stdin.take() {
            let _ = stdin.write_all(b"(exit)\n");
        }
        let _ = self.process.wait();
    }
}

impl Drop for Z3SolverSession {
    fn drop(&mut self) {
        // Send exit signal to Z3 if it's still running
        if let Some(mut stdin) = self.process.stdin.take() {
            let _ = stdin.write_all(b"(exit)\n");
        }
        // Force-kill if still alive to prevent zombie processes and thread hangs
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
