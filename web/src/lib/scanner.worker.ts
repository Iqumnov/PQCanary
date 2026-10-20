// Import the Wasm initialization function and the exposed WasmScanner struct.
// Note: This path assumes `wasm-pack build --target web` has been executed in the `core` directory.
import init, { WasmScanner } from "../../../core/pkg/pqcanary_core.js";

/// The WebWorker ensures that the intense multi-threaded Rust AST scanning
/// does not block the Solid.js UI main thread, keeping the dashboard flawlessly at 60FPS.
self.onmessage = async (event: MessageEvent<string>) => {
  const targetDir = event.data;

  try {
    // Initialize the WebAssembly module payload
    await init();
    
    // Instantiate the Rust Wasm engine with the target directory
    const scanner = new WasmScanner(targetDir);
    
    // Execute the physical AST parsing and serialize the results
    const resultJson = scanner.execute_scan();
    
    // Parse the JSON payload back into strictly typed TypeScript objects
    const results = JSON.parse(resultJson);
    
    // Stream the results back to the Solid.js UI layer
    self.postMessage({ status: "success", data: results });
  } catch (error) {
    self.postMessage({ status: "error", error: String(error) });
  }
};
