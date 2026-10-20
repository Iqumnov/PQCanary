use pqcanary_core::bio::in_vivo_crypto::{ThermodynamicFolder, GeneticScaffolder};

#[test]
fn test_thermodynamic_folding_santalucia() {
    let folder = ThermodynamicFolder::new();
    
    // A sequence with a 4bp stem (GCGC), 3bp loop (AAA), and reverse complement stem (GCGC)
    let seq = "GCGCAAAGCGC";
    let thermo = folder.analyze(seq);
    
    // Expect Tm > 30°C
    assert!(thermo.tm_celsius > 30.0);
    // GC content should be 8/11 = 0.727
    assert!(thermo.gc_content > 0.5);
    
    // Hairpin risk: GCGC stem + AAA loop + GCGC stem
    assert!(thermo.has_hairpin_risk);
    assert!(thermo.max_hairpin_stem_length >= 4);
    
    // An unstable AT-rich sequence
    let seq2 = "ATATATAT";
    let thermo2 = folder.analyze(seq2);
    assert!(thermo2.tm_celsius < thermo.tm_celsius);
}

#[test]
fn test_nand_gate_compilation_and_toxicity() {
    let scaffolder = GeneticScaffolder::new();
    let gate = scaffolder.generate_nand_promoter();
    
    assert_eq!(gate.gate_type, "NAND");
    assert!(gate.parts_used.contains(&"BBa_J23100".to_string())); // Constitutive promoter
    
    // The NAND gate uses standard BioBrick parts, meaning GC content should be reasonable
    assert!(gate.thermodynamic_analysis.gc_content > 0.2);
    assert!(gate.thermodynamic_analysis.gc_content < 0.8);
    
    // Ensure the FASTA generation is valid
    assert!(gate.fasta_output.starts_with(">PQCanary_NAND_Gate"));
    assert!(gate.full_sequence.contains("AAAA")); // Spacers used in scaffold
}
