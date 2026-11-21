import { Title, Meta, Link } from "@solidjs/meta";

export default function CliReferenceDoc() {
  return (
    <main style={{ "max-width": "860px", margin: "0 auto", padding: "4rem 1.5rem", "font-family": "system-ui, -apple-system, sans-serif", color: "#F5F5F4", "line-height": "1.7" }}>
      <Title>CLI Command Reference Manual | PQCanary Documentation</Title>
      <Meta name="description" content="Complete command-line interface (CLI) manual for PQCanary: subcommands, flags, options, exit codes, and environment variables." />
      <Meta property="og:title" content="CLI Command Reference Manual | PQCanary Documentation" />
      <Meta property="og:description" content="Complete command-line interface (CLI) manual for PQCanary: subcommands, flags, options, exit codes, and environment variables." />
      <Meta property="og:image" content="https://pqcanary.iqumnov.com/og-banner.png" />
      <Meta name="twitter:card" content="summary_large_image" />
      <Meta name="twitter:image" content="https://pqcanary.iqumnov.com/og-banner.png" />
      <Link rel="canonical" href="https://pqcanary.iqumnov.com/docs/cli-reference" />

      <nav style={{ "margin-bottom": "2rem" }}>
        <a href="/docs" style={{ color: "#F59E0B", "text-decoration": "none", "font-size": "0.95rem", "font-weight": "500" }}>
          ← Back to Documentation
        </a>
      </nav>

      <header style={{ "margin-bottom": "2.5rem" }}>
        <h1 style={{ "font-size": "2.5rem", "font-weight": "800", color: "#FFFFFF", "margin-bottom": "0.5rem" }}>
          CLI Command Reference Manual
        </h1>
        <p style={{ "font-size": "1.1rem", color: "#A8A29E" }}>
          Complete parameters, subcommands, exit codes, and CI/CD integration options.
        </p>
      </header>

      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "1rem" }}>Core Commands Synopsis</h2>
        <pre style={{ background: "#141210", padding: "1.25rem", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.1)", overflow: "auto", "font-family": "'JetBrains Mono', monospace", color: "#FDE68A", "font-size": "0.9rem" }}>
pqcanary scan &lt;PATH&gt; [--strict] [-f &lt;FORMAT&gt;] [-o &lt;FILE&gt;]
pqcanary cbom &lt;PATH&gt; [-o &lt;FILE&gt;]
pqcanary cbom-attest &lt;CBOM_PATH&gt; [--project &lt;NAME&gt;] [--signer &lt;EMAIL&gt;]
pqcanary probe-tls &lt;TARGET&gt;
pqcanary probe-ssh &lt;TARGET&gt;
pqcanary acvp [--library &lt;NAME&gt;] [--vector-file &lt;PATH&gt;]
pqcanary concolic &lt;FILE&gt;
pqcanary constant-time --routine &lt;NAME&gt; [--samples &lt;COUNT&gt;]
pqcanary serve [--port &lt;PORT&gt;]
        </pre>
      </section>

      <section style={{ "margin-bottom": "3rem" }}>
        <h2 style={{ "font-size": "1.6rem", color: "#FFFFFF", "margin-bottom": "1rem" }}>Exit Codes</h2>
        <ul style={{ color: "#D6D3D1", "padding-left": "1.25rem" }}>
          <li><code style={{ color: "#10B981" }}>0</code> — Clean scan (no vulnerabilities detected).</li>
          <li><code style={{ color: "#EF4444" }}>1</code> — Critical / High severity findings detected in strict CI mode.</li>
          <li><code style={{ color: "#F59E0B" }}>2</code> — CLI execution error or invalid parameters.</li>
        </ul>
      </section>
    </main>
  );
}

