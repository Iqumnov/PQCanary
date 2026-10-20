use pqcanary_core::refactor::cognitive_security::CognitiveSecurityAnalyzer;

#[test]
fn test_halstead_complexity() {
    let analyzer = CognitiveSecurityAnalyzer::new();
    let source = "
        fn calculate(a: i32, b: i32) -> i32 {
            if a > 10 && b < 20 {
                return a * b + 5;
            }
            a - b
        }
    ";
    
    let metrics = analyzer.analyze_halstead(source);
    // There are distinct operators: >, &&, <, *, +, -
    assert!(metrics.unique_operators >= 5);
    // Operands: a, b, 10, 20, 5
    assert!(metrics.unique_operands >= 3);
    
    assert!(metrics.difficulty() > 0.0);
    assert!(metrics.volume() > 0.0);
    assert!(metrics.effort() > 0.0);
}

#[test]
fn test_cyclomatic_complexity() {
    let analyzer = CognitiveSecurityAnalyzer::new();
    let source = "
        if a && b { 
            while c { d; }
        } else if e {
            f;
        }
    ";
    
    let cyclo = analyzer.compute_cyclomatic_complexity(source);
    // Base(1) + if(1) + &&(1) + while(1) + else if(1) = 5
    assert_eq!(cyclo, 5);
}
