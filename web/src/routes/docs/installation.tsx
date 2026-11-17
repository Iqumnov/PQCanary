import { Title, Meta, Link } from "@solidjs/meta";

export default function InstallationDoc() {
  return (
    <main style={{ "max-width": "860px", margin: "0 auto", padding: "4rem 1.5rem", "font-family": "system-ui, -apple-system, sans-serif", color: "#F5F5F4", "line-height": "1.7" }}>
      <Title>Installation &amp; Standalone Binaries | PQCanary Documentation</Title>
      <Meta name="description" content="Install PQCanary across Linux (glibc & Void/Alpine musl), macOS, Windows, Cargo, and Docker. Zero external dependencies required." />
      <Meta property="og:title" content="Installation &amp; Standalone Binaries | PQCanary Documentation" />
      <Meta property="og:description" content="Install PQCanary across Linux (glibc & Void/Alpine musl), macOS, Windows, Cargo, and Docker. Zero external dependencies required." />
      <Meta property="og:image" content="https://pqcanary.pages.dev/og-banner.png" />
      <Meta name="twitter:card" content="summary_large_image" />
      <Meta name="twitter:image" content="https://pqcanary.pages.dev/og-banner.png" />
      <Link rel="canonical" href="https://pqcanary.pages.dev/docs/installation" />

      <nav style={{ "margin-bottom": "2rem" }}>
        <a href="/docs" style={{ color: "#F59E0B", "text-decoration": "none", "font-size": "0.95rem", "font-weight": "500" }}>
          ← Back to Documentation
        </a>
      </nav>

      <header style={{ "margin-bottom": "2.5rem" }}>
        <h1 style={{ "font-size": "2.5rem", "font-weight": "800", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>
          Installation &amp; Pre-Compiled Binaries
        </h1>
        <p style={{ "font-size": "1.1rem", color: "#A8A29E" }}>
          Get PQCanary running in seconds with universal binary installers, distribution packages, container images, or source compilation.
        </p>
      </header>

      {/* Architecture & Delivery Model */}
      <section style={{ "margin-bottom": "3rem", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.08)", "border-radius": "12px", padding: "1.5rem" }}>
        <h2 style={{ "font-size": "1.4rem", color: "#F59E0B", "margin-bottom": "0.75rem" }}>
          Platform Architecture: Single Self-Contained Binary
        </h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "0.75rem", "font-size": "0.95rem" }}>
          PQCanary follows modern developer tool architecture: <strong>all 42 security tools and services are compiled into a single, standalone executable (<code>pqcanary</code>) with zero dynamic runtime dependencies</strong>.
        </p>
        <ul style={{ color: "#A8A29E", "font-size": "0.9rem", "padding-left": "1.25rem", "line-height": "1.6" }}>
          <li><strong>No Fragmented Daemons:</strong> You do not need to install or configure separate database, scanner, or web services.</li>
          <li><strong>Activated On Demand:</strong> Run ad-hoc scans (<code>pqcanary scan .</code>), generate CBOMs (<code>pqcanary cbom .</code>), launch the background REST daemon (<code>pqcanary serve --port 8080</code>), or watch files (<code>pqcanary watch</code>).</li>
          <li><strong>Companion MCP Daemon:</strong> The installer also sets up <code>pqcanary-mcp</code>, the Model Context Protocol server for AI coding agents (Claude Desktop, Cursor, Smithery).</li>
        </ul>
      </section>

      {/* 1. Universal Shell Installer */}
      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "0.75rem" }}>1. Universal Shell Installer (Linux &amp; macOS)</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          The official shell installer automatically detects your operating system (`uname -s`), CPU architecture (`uname -m`), and C standard library (`glibc` vs `musl`), installs both <code>pqcanary</code> and <code>pqcanary-mcp</code>, and confirms execution:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#FDE68A", "font-size": "0.9rem" }}>
curl -sSf https://raw.githubusercontent.com/Iqumnov/PQCanary/main/scripts/install-bin.sh | sh
        </pre>
        <h3 style={{ "font-size": "1.1rem", color: "#E7E5E4", "margin-top": "1rem", "margin-bottom": "0.5rem" }}>Custom Installer Flags (Environment Variables)</h3>
        <p style={{ color: "#A8A29E", "font-size": "0.9rem", "margin-bottom": "0.5rem" }}>
          For non-interactive CI/CD runners or restricted permission environments:
        </p>
        <pre style={{ background: "#141210", padding: "1rem", "border-radius": "8px", border: "1px solid rgba(255,255,255,0.06)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#D6D3D1", "font-size": "0.85rem" }}>
# Install to custom directory without sudo
PQCANARY_INSTALL_DIR="$HOME/bin" PQCANARY_NO_SUDO=1 curl -sSf https://raw.githubusercontent.com/Iqumnov/PQCanary/main/scripts/install-bin.sh | sh

# Pin a specific release version
PQCANARY_VERSION="v0.1.0" curl -sSf https://raw.githubusercontent.com/Iqumnov/PQCanary/main/scripts/install-bin.sh | sh
        </pre>
      </section>

      {/* 2. Homebrew */}
      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "0.75rem" }}>2. Homebrew (macOS &amp; Linux)</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          Install via Homebrew on Apple Silicon (M1/M2/M3/M4), Intel Macs, or Linux:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#60A5FA", "font-size": "0.9rem" }}>
# Install via official Homebrew tap formula
brew install --build-from-source packaging/homebrew/pqcanary.rb

# Verify installation
pqcanary --version
        </pre>
      </section>

      {/* 3. Arch Linux AUR */}
      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "0.75rem" }}>3. Arch Linux (AUR)</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          Arch Linux users can build and install via <code>makepkg</code> or an AUR helper:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#C084FC", "font-size": "0.9rem" }}>
cd packaging/arch-linux
makepkg -si
        </pre>
      </section>

      {/* 4. Void Linux & Alpine Linux (Static musl) */}
      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "0.75rem" }}>4. Void Linux &amp; Alpine Linux (Static musl)</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          PQCanary officially provides 100% static musl binaries compiled against <code>x86_64-unknown-linux-musl</code> with zero dynamic runtime dependencies:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#A7F3D0", "font-size": "0.9rem" }}>
# Direct static musl binary download
curl -LO https://github.com/Iqumnov/PQCanary/releases/download/v0.1.0/pqcanary-linux-x86_64-musl.tar.gz
tar -xzf pqcanary-linux-x86_64-musl.tar.gz
sudo install -m 755 pqcanary /usr/local/bin/
        </pre>
      </section>

      {/* 5. Docker Container */}
      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "0.75rem" }}>5. Docker Container</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          Run zero-installation containerized scans across any local directory:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#38BDF8", "font-size": "0.9rem" }}>
# Pull and scan current directory in Docker
docker run --rm -v "$(pwd):/workspace" ghcr.io/iqumnov/pqcanary:latest scan /workspace
        </pre>
      </section>

      {/* 6. Cargo Source Compilation */}
      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "0.75rem" }}>6. Rust Cargo Package Manager</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          If you have a standard Rust toolchain (1.80.0+), install directly from source:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#BAE6FD", "font-size": "0.9rem" }}>
cargo install --git https://github.com/Iqumnov/PQCanary.git pqcanary-cli --bin pqcanary --bin pqcanary-mcp
        </pre>
      </section>
    </main>
  );
}

