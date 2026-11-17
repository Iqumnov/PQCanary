import { Title, Meta, Link } from "@solidjs/meta";

export default function Fips203Doc() {
  return (
    <main style={{ "max-width": "860px", margin: "0 auto", padding: "4rem 1.5rem", "font-family": "system-ui, -apple-system, sans-serif", color: "#F5F5F4", "line-height": "1.7" }}>
      <Title>NIST FIPS 203 (ML-KEM) Post-Quantum Cryptography Audit | PQCanary</Title>
      <Meta name="description" content="Technical audit guide for NIST FIPS 203 (Module-Lattice Key Encapsulation Mechanism / Kyber). Audit security categories, detect KyberSlash timing defects, and generate hybrid migration patches." />
      <Meta property="og:title" content="NIST FIPS 203 (ML-KEM) Post-Quantum Cryptography Audit | PQCanary" />
      <Meta property="og:description" content="Technical audit guide for NIST FIPS 203 (ML-KEM). Audit security categories, detect KyberSlash timing defects, and generate hybrid migration patches." />
      <Meta property="og:image" content="https://pqcanary.pages.dev/og-banner.png" />
      <Meta name="twitter:card" content="summary_large_image" />
      <Meta name="twitter:image" content="https://pqcanary.pages.dev/og-banner.png" />
      <Link rel="canonical" href="https://pqcanary.pages.dev/docs/fips-203" />

      <nav style={{ "margin-bottom": "2rem" }}>
        <a href="/docs" style={{ color: "#F59E0B", "text-decoration": "none", "font-size": "0.95rem", "font-weight": "500" }}>
          ← Back to Documentation
        </a>
      </nav>

      <header style={{ "margin-bottom": "2.5rem" }}>
        <h1 style={{ "font-size": "2.5rem", "font-weight": "800", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>
          NIST FIPS 203: ML-KEM Audit Engine
        </h1>
        <p style={{ "font-size": "1.1rem", color: "#A8A29E" }}>
          Automated cryptographic inspection, NTT polynomial overflow detection, and KyberSlash timing leakage prevention.
        </p>
      </header>

      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "1rem" }}>FIPS 203 Parameter Sets</h2>
        <div style={{ overflow: "auto", "margin-bottom": "1.5rem" }}>
          <table style={{ width: "100%", "border-collapse": "collapse", "font-size": "0.95rem", "text-align": "left" }}>
            <thead>
              <tr style={{ "border-bottom": "1px solid rgba(255,255,255,0.15)", color: "#F59E0B" }}>
                <th style={{ padding: "0.75rem" }}>Parameter Set</th>
                <th style={{ padding: "0.75rem" }}>Security Category</th>
                <th style={{ padding: "0.75rem" }}>Public Key (Bytes)</th>
                <th style={{ padding: "0.75rem" }}>Ciphertext (Bytes)</th>
                <th style={{ padding: "0.75rem" }}>NIST / NSA Mandate</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ "border-bottom": "1px solid rgba(255,255,255,0.06)" }}>
                <td style={{ padding: "0.75rem", "font-weight": "600" }}>ML-KEM-512</td>
                <td style={{ padding: "0.75rem" }}>Category 1 (AES-128)</td>
                <td style={{ padding: "0.75rem" }}>800</td>
                <td style={{ padding: "0.75rem" }}>768</td>
                <td style={{ padding: "0.75rem" }}>General Purpose</td>
              </tr>
              <tr style={{ "border-bottom": "1px solid rgba(255,255,255,0.06)" }}>
                <td style={{ padding: "0.75rem", "font-weight": "600" }}>ML-KEM-768</td>
                <td style={{ padding: "0.75rem" }}>Category 3 (AES-192)</td>
                <td style={{ padding: "0.75rem" }}>1184</td>
                <td style={{ padding: "0.75rem" }}>1088</td>
                <td style={{ padding: "0.75rem", color: "#10B981" }}>CNSA 2.0 Primary Choice</td>
              </tr>
              <tr style={{ "border-bottom": "1px solid rgba(255,255,255,0.06)" }}>
                <td style={{ padding: "0.75rem", "font-weight": "600" }}>ML-KEM-1024</td>
                <td style={{ padding: "0.75rem" }}>Category 5 (AES-256)</td>
                <td style={{ padding: "0.75rem" }}>1568</td>
                <td style={{ padding: "0.75rem" }}>1568</td>
                <td style={{ padding: "0.75rem" }}>High-Assurance / Top Secret</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "1rem" }}>Auditing Codebases for FIPS 203 Readiness</h2>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#FDE68A", "font-size": "0.9rem" }}>
# Run a full FIPS 203 audit on your repository
pqcanary scan . --rule-tag fips203 -f markdown -o fips203-audit.md
        </pre>
      </section>
    </main>
  );
}

