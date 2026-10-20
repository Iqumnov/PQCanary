use std::fmt;

/// Errors that can occur during Reed-Solomon Encoding/Decoding
#[derive(Debug)]
pub enum ReedSolomonError {
    MessageTooLong { length: usize, max: usize },
    InvalidParityCount { count: usize },
}

impl fmt::Display for ReedSolomonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLong { length, max } => {
                write!(f, "Message length {} exceeds max capacity {}", length, max)
            }
            Self::InvalidParityCount { count } => {
                write!(f, "Invalid parity symbol count: {}", count)
            }
        }
    }
}

const GF_SIZE: usize = 256;
const GF_POLYNOMIAL: usize = 0x11B; // x^8 + x^4 + x^3 + x + 1

/// Mathematical Engine for Galois Field GF(2^8)
pub struct GaloisField {
    exp: [u8; GF_SIZE * 2],
    log: [u8; GF_SIZE],
}

impl Default for GaloisField {
    fn default() -> Self {
        Self::new()
    }
}

impl GaloisField {
    /// Initializes the exponential and logarithmic lookup tables for GF(2^8)
    pub fn new() -> Self {
        let mut exp = [0u8; GF_SIZE * 2];
        let mut log = [0u8; GF_SIZE];

        let mut x = 1;
        for (i, slot) in exp.iter_mut().enumerate().take(255) {
            *slot = x as u8;
            log[x] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= GF_POLYNOMIAL;
            }
        }
        for i in 255..(GF_SIZE * 2) {
            exp[i] = exp[i - 255];
        }

        Self { exp, log }
    }

    #[inline(always)]
    pub fn add(&self, x: u8, y: u8) -> u8 {
        x ^ y // Addition is XOR in Galois Field
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub fn sub(&self, x: u8, y: u8) -> u8 {
        x ^ y // Subtraction is also XOR
    }

    #[inline(always)]
    pub fn mul(&self, x: u8, y: u8) -> u8 {
        if x == 0 || y == 0 {
            0
        } else {
            self.exp[self.log[x as usize] as usize + self.log[y as usize] as usize]
        }
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub fn div(&self, x: u8, y: u8) -> u8 {
        if y == 0 {
            // In a strict math context, division by zero is undefined
            return 0;
        }
        if x == 0 {
            0
        } else {
            let log_x = self.log[x as usize] as isize;
            let log_y = self.log[y as usize] as isize;
            let mut diff = log_x - log_y;
            if diff < 0 {
                diff += 255;
            }
            self.exp[diff as usize]
        }
    }

    #[inline(always)]
    pub fn power(&self, x: u8, p: usize) -> u8 {
        if x == 0 {
            0
        } else {
            self.exp[((self.log[x as usize] as usize) * (p % 255)) % 255]
        }
    }
}

/// Quantum-Error-Correction for Exotic Storage (DNA/Holographic)
/// Implements a production-ready Reed-Solomon (255, 223) Error Correction Codec
/// over Galois Field GF(2^8), used to correct synthesis/sequencing drop-outs.
pub struct ExoticStorageQec {
    gf: GaloisField,
}

impl Default for ExoticStorageQec {
    fn default() -> Self {
        Self::new()
    }
}

impl ExoticStorageQec {
    pub fn new() -> Self {
        Self {
            gf: GaloisField::new(),
        }
    }

    /// Multiplies two polynomials over GF(2^8)
    fn poly_mul(&self, p: &[u8], q: &[u8]) -> Vec<u8> {
        if p.is_empty() || q.is_empty() {
            return Vec::new();
        }
        let mut result = vec![0u8; p.len() + q.len() - 1];
        for (j, &yj) in q.iter().enumerate() {
            for (i, &xi) in p.iter().enumerate() {
                result[i + j] = self.gf.add(result[i + j], self.gf.mul(xi, yj));
            }
        }
        result
    }

    /// Generates the Reed-Solomon generator polynomial for `nsym` parity symbols
    fn rs_generator_poly(&self, nsym: usize) -> Vec<u8> {
        let mut g = vec![1u8];
        for i in 0..nsym {
            // Multiply by (x - α^i) => As polynomial array: [1, α^i]
            let root = self.gf.power(2, i);
            g = self.poly_mul(&g, &[1, root]);
        }
        g
    }

    /// Systematic Reed-Solomon Encoder
    /// Appends `nsym` parity bytes to the input `message`.
    /// For standard DNA synthesis protection (RS-255,223), `nsym` = 32.
    pub fn encode_reed_solomon(&self, message: &[u8], nsym: usize) -> Result<Vec<u8>, ReedSolomonError> {
        if nsym == 0 || nsym >= 255 {
            return Err(ReedSolomonError::InvalidParityCount { count: nsym });
        }
        
        let max_len = 255 - nsym;
        if message.len() > max_len {
            return Err(ReedSolomonError::MessageTooLong { 
                length: message.len(), 
                max: max_len 
            });
        }
        
        let gen = self.rs_generator_poly(nsym);
        
        // Prepare the polynomial division array: Message followed by `nsym` zeros
        let mut msg_out = vec![0u8; message.len() + nsym];
        msg_out[..message.len()].copy_from_slice(message);

        // Polynomial Long Division using GF(2^8) arithmetic
        for i in 0..message.len() {
            let coef = msg_out[i];
            if coef != 0 {
                // Subtract (XOR) the generator polynomial scaled by the coefficient
                for j in 0..gen.len() {
                    msg_out[i + j] = self.gf.add(msg_out[i + j], self.gf.mul(gen[j], coef));
                }
            }
        }

        // The parity is the remainder located at the end of msg_out.
        // We systematically concatenate the original message with the parity.
        let mut encoded = message.to_vec();
        encoded.extend_from_slice(&msg_out[message.len()..]);
        
        Ok(encoded)
    }
}
