import { Title, Meta, Link } from "@solidjs/meta";

export default function CbomAttestationDoc() {
  return (
    <main style={{ "max-width": "860px", margin: "0 auto", padding: "4rem 1.5rem", "font-family": "system-ui, -apple-system, sans-serif", color: "#F5F5F4", "line-height": "1.7" }}>
      <Title>CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) &amp; Sigstore Cosign Attestation | PQCanary</Title>
      <Meta name="description" content="Generate and cryptographically attest CycloneDX 1.6 Cryptographic Bills of Materials (CBOM) using in-toto SLSA Provenance v1.0 and Sigstore Cosign DSSE envelopes." />
      <Meta property="og:title" content="CycloneDX 1.6 CBOM &amp; Sigstore Cosign Attestation | PQCanary" />
      <Meta property="og:description" content="Generate and cryptographically attest CycloneDX 1.6 Cryptographic Bills of Materials (CBOM) using in-toto SLSA Provenance v1.0 and Sigstore Cosign DSSE envelopes." />
      <Meta property="og:image" content="https://pqcanary.pages.dev/og-banner.png" />
      <Meta name="twitter:card" content="summary_large_image" />
      <Meta name="twitter:image" content="https://pqcanary.pages.dev/og-banner.png" />
      <Link rel="canonical" href="https://pqcanary.pages.dev/docs/cbom-attestation" />

      <nav style={{ "margin-bottom": "2rem" }}>
        <a href="/docs" style={{ color: "#F59E0B", "text-decoration": "none", "font-size": "0.95rem", "font-weight": "500" }}>
          ← Back to Documentation
        </a>
      </nav>

      <header style={{ "margin-bottom": "2.5rem" }}>
        <h1 style={{ "font-size": "2.5rem", "font-weight": "800", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>
          CycloneDX 1.6 CBOM &amp; Sigstore Attestation
        </h1>
        <p style={{ "font-size": "1.1rem", color: "#A8A29E" }}>
          Create tamper-proof cryptographic software supply chain records with Dead Simple Signing Envelopes (DSSE).
        </p>
      </header>

      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "1rem" }}>1. Generate a CycloneDX 1.6 CBOM</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          PQCanary automatically inspects your repository and constructs a valid CycloneDX 1.6 Cryptographic Bill of Materials detailing every key exchange algorithm, signature routine, curve length, and quantum vulnerability:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#BAE6FD", "font-size": "0.9rem" }}>
# Generate CBOM in CycloneDX 1.6 JSON format
pqcanary cbom . -o cbom.json
        </pre>
      </section>

      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "1rem" }}>2. Sign with in-toto SLSA Provenance &amp; Cosign</h2>
        <p style={{ color: "#D6D3D1", "margin-bottom": "1rem" }}>
          Wrap the generated CBOM in a cryptographic DSSE envelope signed with your developer identity:
        </p>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#FDE68A", "font-size": "0.9rem" }}>
pqcanary cbom-attest ./cbom.json --project enterprise-core --signer user@domain.com
        </pre>
      </section>
    </main>
  );
}

