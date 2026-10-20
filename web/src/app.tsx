import { MetaProvider, Title, Meta, Link } from "@solidjs/meta";
import { Router } from "@solidjs/router";
import { FileRoutes } from "@solidjs/start/router";
import { Suspense, onMount } from "solid-js";
import "./app.css";

export default function App() {
  onMount(() => {
    // Production PWA Service Worker Registration
    if (typeof window !== "undefined" && "serviceWorker" in navigator) {
      const registerSW = () => {
        navigator.serviceWorker
          .register("/sw.js", { scope: "/" })
          .then((registration) => {
            console.log("PQCanary PWA: Service Worker registered with scope:", registration.scope);
          })
          .catch((error) => {
            console.warn("PQCanary PWA: Service Worker registration failed:", error);
          });
      };

      if (document.readyState === "complete") {
        registerSW();
      } else {
        window.addEventListener("load", registerSW);
      }
    }
  });

  return (
    <Router
      root={(props) => (
        <MetaProvider>
          <Title>PQCanary | Enterprise Post-Quantum Cryptographic Scanner</Title>
          
          {/* Progressive Web App (PWA) Standards Compliance */}
          <Meta name="theme-color" content="#F59E0B" />
          <Meta name="color-scheme" content="dark light" />
          <Meta name="application-name" content="PQCanary" />
          <Meta name="description" content="Enterprise post-quantum cryptographic auditor, CBOM generator, and NIST FIPS 203/204 migration guardrail." />
          
          {/* Apple iOS PWA Capabilities */}
          <Meta name="apple-mobile-web-app-capable" content="yes" />
          <Meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
          <Meta name="apple-mobile-web-app-title" content="PQCanary" />
          <Link rel="apple-touch-icon" href="/icons/apple-touch-icon.png" />
          
          {/* Manifest & Icon Declarations */}
          <Link rel="manifest" href="/manifest.webmanifest" />
          <Link rel="icon" type="image/svg+xml" href="/PQCanary.svg" />
          <Link rel="icon" type="image/png" sizes="192x192" href="/icons/icon-192.png" />
          <Link rel="icon" type="image/png" sizes="512x512" href="/icons/icon-512.png" />

          <a href="#main-content" class="skip-link" style="position:absolute; left:-9999px; z-index:999; padding:1em; background-color:#000; color:#fff; text-decoration:none;">
            Skip to main content
          </a>
          <Suspense fallback={<div>Loading PQCanary Engine...</div>}>
            {props.children}
          </Suspense>
        </MetaProvider>
      )}
    >
      <FileRoutes />
    </Router>
  );
}
