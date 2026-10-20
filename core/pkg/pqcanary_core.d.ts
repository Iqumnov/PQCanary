/* tslint:disable */
/* eslint-disable */

export interface ComprehensiveFinding {
  file_path: string;
  vulnerability_class: string;
  description: string;
  severity: string;
  line_number: number;
  remediation: string;
  rule_id?: string;
  quantum_risk?: string;
  confidence?: string;
  snippet?: string;
  column_number?: number;
  fingerprint?: string;
}

export class WasmScanner {
  free(): void;
  constructor(target_dir: string);
  execute_scan(): string;
  static scan_source(source_code: string, file_name: string): string;
  static export_sarif(findings_json: string, repository_name?: string): string;
  static compare_baseline(current_json: string, baseline_json: string): string;
  static export_cbom(findings_json: string, target_path: string): string;
  static compute_cfg(source_code: string): string;
  static simulate_quantum(num_qubits: number, target_bitstring: string, shots?: number): string;
  static classify_algorithm(algorithm: string): string;
  static export_hott_proof(algorithm: string): string;
  static simulate_thermodynamics(total_gates: number, erased_bits: number): string;
  static generate_patch(file_path: string, source: string): string;
}

export default function init(input?: RequestInfo | BufferSource | WebAssembly.Module): Promise<any>;
