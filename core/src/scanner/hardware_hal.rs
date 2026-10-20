//! Hardware Abstraction Layer (HAL) for interfacing with physical side-channel 
//! analysis equipment like ChipWhisperer, oscilloscopes, and laser injection setups.
//! 
//! This module provides the physical grounding for the mathematical DFA 
//! (Differential Fault Analysis) and DPA (Differential Power Analysis) engines.

use std::time::Duration;
use serialport::SerialPort;

pub struct PhysicalGlitchTarget {
    pub port_name: String,
    pub baud_rate: u32,
    port: Option<Box<dyn SerialPort>>,
}

impl PhysicalGlitchTarget {
    pub fn new(port_name: &str) -> Self {
        Self {
            port_name: port_name.to_string(),
            baud_rate: 115200,
            port: None,
        }
    }

    /// Connect to the physical serial interface (e.g., /dev/ttyUSB0 or COM3).
    pub fn connect(&mut self) -> Result<(), String> {
        let port = serialport::new(&self.port_name, self.baud_rate)
            .timeout(Duration::from_millis(100))
            .open()
            .map_err(|e| format!("Failed to open serial port: {}", e))?;
        
        self.port = Some(port);
        Ok(())
    }

    /// Send SPI/UART command to FPGA to arm the laser pulse at specific cycle
    pub fn arm_laser(&mut self, cycle_offset: u32) -> Result<(), String> {
        if let Some(ref mut port) = self.port {
            let cmd = format!("ARM {}\n", cycle_offset);
            port.write_all(cmd.as_bytes()).map_err(|e| e.to_string())?;
            port.flush().map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Port not connected".to_string())
        }
    }

    /// Fire a glitch and capture the resulting ciphertext.
    pub fn fire_glitch(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if plaintext.len() != 16 {
            return Err(format!("Plaintext length must be exactly 16 bytes for AES-128 glitch target, got {}", plaintext.len()));
        }
        if let Some(ref mut port) = self.port {
            // Trigger physical execution
            port.write_all(b"FIRE\n").map_err(|e| e.to_string())?;
            port.write_all(plaintext).map_err(|e| e.to_string())?;
            
            // Read response
            let mut buf = vec![0; 16]; // AES block size
            port.read_exact(&mut buf).map_err(|e| e.to_string())?;
            Ok(buf)
        } else {
            Err("Port not connected".to_string())
        }
    }
}

/// Digital Signal Processing for power trace alignment.
pub struct TraceAligner;

impl TraceAligner {
    /// Align thousands of noisy oscilloscope traces using Fast Fourier Transform (FFT) 
    /// or Sum of Absolute Differences (SAD) before mathematical analysis.
    pub fn align_traces_sad(reference_trace: &[f32], target_traces: &mut [Vec<f32>]) {
        if reference_trace.is_empty() {
            return;
        }

        let search_window = 100usize;
        for trace in target_traces.iter_mut() {
            if trace.len() < reference_trace.len() {
                continue;
            }

            let mut best_offset = 0;
            let mut min_diff = f32::MAX;
            let max_offset = (trace.len() - reference_trace.len()).min(search_window);

            for offset in 0..=max_offset {
                let mut diff = 0.0f32;
                for (i, &ref_val) in reference_trace.iter().enumerate() {
                    let d = (ref_val - trace[offset + i]).abs();
                    diff += if d.is_finite() { d } else { 0.0 };
                }
                if diff.is_finite() && diff < min_diff {
                    min_diff = diff;
                    best_offset = offset;
                }
            }

            // Shift the trace logically based on best_offset
            trace.rotate_left(best_offset);
        }
    }
}
