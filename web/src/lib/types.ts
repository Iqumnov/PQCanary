/// Strictly typed payload crossing the Wasm -> JS boundary.
/// Represents the mathematical vulnerability signature extracted by the Rust engine.
export interface SecureMaterial {
    raw_material: number[];
    file_path: string;
    line_number: number;
}
