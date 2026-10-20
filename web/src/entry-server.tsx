import { createHandler, StartServer } from "@solidjs/start/server";

export default createHandler(() => (
  <StartServer
    document={({ assets, children, scripts }) => (
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>PQCanary | Enterprise Post-Quantum Cryptographic Scanner</title>
          <meta name="description" content="Enterprise post-quantum cryptographic auditor, CBOM generator, and NIST FIPS 203/204 migration guardrail." />
          <meta name="keywords" content="post-quantum, cryptography, PQC, NIST FIPS 203, FIPS 204, ML-KEM, ML-DSA, CBOM, CycloneDX, cybersecurity" />
          <meta name="author" content="PQCanary" />
          <meta name="robots" content="index, follow" />
          <meta name="theme-color" content="#F59E0B" />
          <meta name="color-scheme" content="dark light" />

          {/* Open Graph & Social Card SEO */}
          <meta property="og:type" content="website" />
          <meta property="og:site_name" content="PQCanary" />
          <meta property="og:title" content="PQCanary | Enterprise Post-Quantum Cryptographic Security Platform" />
          <meta property="og:description" content="Enterprise post-quantum cryptographic auditor, CBOM generator, and NIST FIPS 203/204 migration guardrail." />
          <meta property="og:image" content="/icons/icon-512.png" />
          <meta name="twitter:card" content="summary_large_image" />
          <meta name="twitter:title" content="PQCanary | Enterprise Post-Quantum Cryptographic Security Platform" />
          <meta name="twitter:description" content="Enterprise post-quantum cryptographic auditor, CBOM generator, and NIST FIPS 203/204 migration guardrail." />
          <meta name="twitter:image" content="/icons/icon-512.png" />

          {/* Progressive Web App (PWA) Manifest & Meta */}
          <link rel="manifest" href="/manifest.webmanifest" />
          <meta name="mobile-web-app-capable" content="yes" />
          <meta name="apple-mobile-web-app-capable" content="yes" />
          <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
          <meta name="apple-mobile-web-app-title" content="PQCanary" />
          <meta name="application-name" content="PQCanary" />
          <meta name="msapplication-TileColor" content="#0a0a0c" />

          {/* Favicons & App Icons */}
          <link rel="icon" type="image/svg+xml" href="/PQCanary.svg" />
          <link rel="icon" type="image/png" sizes="192x192" href="/icons/icon-192.png" />
          <link rel="icon" type="image/png" sizes="512x512" href="/icons/icon-512.png" />
          <link rel="apple-touch-icon" sizes="180x180" href="/icons/apple-touch-icon.png" />
          {assets}
        </head>
        <body>
          <div id="app">{children}</div>
          {scripts}
        </body>
      </html>
    )}
  />
));
