use pqcanary_core::omega::thermodynamics::ThermodynamicsAnalyzer;

#[test]
fn test_landauer_limit_room_temperature() {
    let analyzer = ThermodynamicsAnalyzer::at_room_temperature();
    let report = analyzer.simulate_landauer_limit(1_000_000, 500_000);
    
    // At 298.15K, Landauer limit is approx 2.85e-21 Joules per bit
    assert!(report.landauer_limit_joules > 2.8e-21);
    assert!(report.landauer_limit_joules < 2.9e-21);
    
    // 500,000 erased bits * 2.85e-21 J = ~1.42e-15 J total heat
    assert!(report.total_dissipation_joules > 1.4e-15);
}

#[test]
fn test_cryogenic_temperature_scaling() {
    // 4 Kelvin (Liquid Helium temp, often used for supercomputing/quantum)
    let analyzer = ThermodynamicsAnalyzer::new(4.0);
    let report = analyzer.simulate_landauer_limit(1_000_000, 500_000);
    
    // Heat dissipation should be significantly lower than room temp
    assert!(report.landauer_limit_joules < 1.0e-22);
}
