import { Title, Meta, Link } from "@solidjs/meta";

export default function DocsIndex() {
  return (
    <main style={{ "max-width": "900px", margin: "0 auto", padding: "4rem 1.5rem", "font-family": "system-ui, -apple-system, sans-serif", color: "#F5F5F4", "line-height": "1.7" }}>
      <Title>PQCanary Documentation & Architectural Manual | Post-Quantum Security</Title>
      <Meta name="description" content="Official documentation for PQCanary: NIST FIPS 203/204 cryptographic scanning, universal binary installation, CBOM generation, and concolic SMT verification." />
      <Meta property="og:title" content="PQCanary Documentation & Architectural Manual" />
      <Meta property="og:description" content="Official documentation for PQCanary: NIST FIPS 203/204 cryptographic scanning, universal binary installation, CBOM generation, and concolic SMT verification." />
      <Meta property="og:image" content="https://pqcanary.iqumnov.com/og-banner.png" />
      <Meta name="twitter:card" content="summary_large_image" />
      <Meta name="twitter:image" content="https://pqcanary.iqumnov.com/og-banner.png" />
      <Link rel="canonical" href="https://pqcanary.iqumnov.com/docs" />

      <nav style={{ "margin-bottom": "2rem" }}>
        <a href="/" style={{ color: "#F59E0B", "text-decoration": "none", "font-size": "0.95rem", "font-weight": "500" }}>
          ← Return to PQCanary Platform
        </a>
      </nav>

      <header style={{ "margin-bottom": "3rem", "border-bottom": "1px solid rgba(255,255,255,0.1)", "padding-bottom": "2rem" }}>
        <h1 style={{ "font-size": "2.75rem", "font-weight": "800", "letter-spacing": "-0.03em", color: "#FFFFFF", "margin-bottom": "0.75rem" }}>
          PQCanary Documentation
        </h1>
        <p style={{ "font-size": "1.2rem", color: "#A8A29E", "max-width": "750px" }}>
          Comprehensive architectural guides, compliance specifications, and CLI references for post-quantum cryptographic security.
        </p>
      </header>

      <div style={{ display: "grid", "grid-template-columns": "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.5rem" }}>
        <a href="/docs/installation" style={{ display: "block", padding: "1.75rem", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", "border-radius": "14px", "text-decoration": "none", color: "inherit", transition: "border-color 0.2s, transform 0.2s" }}>
          <span style={{ display: "inline-block", padding: "0.2rem 0.6rem", background: "rgba(245,158,11,0.15)", color: "#F59E0B", "border-radius": "9999px", "font-size": "0.75rem", "font-weight": "600", "margin-bottom": "0.75rem" }}>v0.1.0</span>
          <h2 style={{ "font-size": "1.35rem", "font-weight": "700", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>Installation &amp; Binaries</h2>
          <p style={{ "font-size": "0.95rem", color: "#A8A29E" }}>Universal standalone curl installer, Void/Alpine musl static binaries, macOS, Windows, and Docker.</p>
        </a>

        <a href="/docs/fips-203" style={{ display: "block", padding: "1.75rem", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", "border-radius": "14px", "text-decoration": "none", color: "inherit", transition: "border-color 0.2s, transform 0.2s" }}>
          <span style={{ display: "inline-block", padding: "0.2rem 0.6rem", background: "rgba(16,185,129,0.15)", color: "#10B981", "border-radius": "9999px", "font-size": "0.75rem", "font-weight": "600", "margin-bottom": "0.75rem" }}>NIST Standard</span>
          <h2 style={{ "font-size": "1.35rem", "font-weight": "700", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>NIST FIPS 203 (ML-KEM)</h2>
          <p style={{ "font-size": "0.95rem", color: "#A8A29E" }}>Module-Lattice Key Encapsulation (Kyber) security parameter audit, KyberSlash side-channel detection, and hybrid migration.</p>
        </a>

        <a href="/docs/cbom-attestation" style={{ display: "block", padding: "1.75rem", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", "border-radius": "14px", "text-decoration": "none", color: "inherit", transition: "border-color 0.2s, transform 0.2s" }}>
          <span style={{ display: "inline-block", padding: "0.2rem 0.6rem", background: "rgba(59,130,246,0.15)", color: "#60A5FA", "border-radius": "9999px", "font-size": "0.75rem", "font-weight": "600", "margin-bottom": "0.75rem" }}>Supply Chain</span>
          <h2 style={{ "font-size": "1.35rem", "font-weight": "700", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>CycloneDX 1.6 CBOM</h2>
          <p style={{ "font-size": "0.95rem", color: "#A8A29E" }}>Cryptographic Bill of Materials generation, SLSA Provenance v1.0, and Sigstore Cosign DSSE attestation.</p>
        </a>

        <a href="/docs/cli-reference" style={{ display: "block", padding: "1.75rem", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", "border-radius": "14px", "text-decoration": "none", color: "inherit", transition: "border-color 0.2s, transform 0.2s" }}>
          <span style={{ display: "inline-block", padding: "0.2rem 0.6rem", background: "rgba(168,85,247,0.15)", color: "#C084FC", "border-radius": "9999px", "font-size": "0.75rem", "font-weight": "600", "margin-bottom": "0.75rem" }}>Reference</span>
          <h2 style={{ "font-size": "1.35rem", "font-weight": "700", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>CLI Command Reference</h2>
          <p style={{ "font-size": "0.95rem", color: "#A8A29E" }}>Complete command-line manual, flags, environment variables, exit codes, and CI/CD integration rules.</p>
        </a>
      </div>
    </main>
  );
}

