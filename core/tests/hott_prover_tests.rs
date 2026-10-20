use pqcanary_core::omega::hott_prover::HottProver;

#[test]
fn test_hott_classification() {
    let prover = HottProver::new();
    
    // Kyber512 is Post-Quantum Safe
    let kyber = prover.classify_algorithm("Kyber512");
    assert!(kyber.is_safe());
    assert!(kyber.severity_message().contains("POST-QUANTUM SAFE"));
    
    // RSA-2048 is Broken by Quantum Computers
    let rsa = prover.classify_algorithm("RSA-2048");
    assert!(!rsa.is_safe());
    assert!(rsa.severity_message().contains("QUANTUM VULNERABLE"));
    
    // AES-128 is weakened by Grover's
    let aes128 = prover.classify_algorithm("AES-128");
    assert!(!aes128.is_safe());
    assert!(aes128.severity_message().contains("QUANTUM VULNERABLE"));
}
