//! Kubernetes Service Mesh & Ingress Post-Quantum Auto-Remediation
//!
//! Generates enterprise-ready cloud-native configurations (Istio EnvoyFilter,
//! Traefik TLSOption, NGINX Ingress annotations, and Kubernetes Gateway API)
//! to inject hybrid X25519MLKEM768 key exchanges with zero downtime.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum K8sIngressPlatform {
    IstioEnvoyFilter,
    TraefikTLSOption,
    NginxIngress,
    GatewayApi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sMeshConfig {
    pub platform: K8sIngressPlatform,
    pub namespace: String,
    pub name: String,
    pub workload_selector: String,
    pub hybrid_group: String,
    pub min_tls_version: String,
}

impl Default for K8sMeshConfig {
    fn default() -> Self {
        Self {
            platform: K8sIngressPlatform::IstioEnvoyFilter,
            namespace: "istio-system".to_string(),
            name: "pqc-hybrid-tls-enforce".to_string(),
            workload_selector: "istio=ingressgateway".to_string(),
            hybrid_group: "X25519MLKEM768".to_string(),
            min_tls_version: "TLSv1_3".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sMeshRemediation {
    pub platform: K8sIngressPlatform,
    pub manifest_yaml: String,
    pub summary: String,
    pub apply_command: String,
    pub rollback_command: String,
    pub verification_probe_command: String,
}

pub struct K8sMeshEngine;

impl K8sMeshEngine {
    /// Generates production-grade Kubernetes manifest for the selected platform
    pub fn generate(config: &K8sMeshConfig) -> K8sMeshRemediation {
        match config.platform {
            K8sIngressPlatform::IstioEnvoyFilter => Self::generate_istio(config),
            K8sIngressPlatform::TraefikTLSOption => Self::generate_traefik(config),
            K8sIngressPlatform::NginxIngress => Self::generate_nginx(config),
            K8sIngressPlatform::GatewayApi => Self::generate_gateway_api(config),
        }
    }

    fn generate_istio(config: &K8sMeshConfig) -> K8sMeshRemediation {
        let yaml = format!(
r#"apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: {}
  namespace: {}
  labels:
    app.kubernetes.io/managed-by: pqcanary
    security.pqcanary.pages.dev/quantum-ready: "true"
spec:
  workloadSelector:
    labels:
      istio: ingressgateway
  configPatches:
    - applyTo: FILTER_CHAIN
      match:
        context: GATEWAY
        listener:
          portNumber: 443
          filterChain:
            filter:
              name: "envoy.filters.network.http_connection_manager"
      patch:
        operation: MERGE
        value:
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3
                  ecdh_curves:
                    - {}
                    - X25519
                    - P-256
                  cipher_suites:
                    - TLS_AES_256_GCM_SHA384
                    - TLS_CHACHA20_POLY1305_SHA256
                    - TLS_AES_128_GCM_SHA256
"#,
            config.name, config.namespace, config.hybrid_group
        );

        K8sMeshRemediation {
            platform: K8sIngressPlatform::IstioEnvoyFilter,
            manifest_yaml: yaml.clone(),
            summary: format!("Istio EnvoyFilter injecting {} and TLS 1.3 downstream parameters.", config.hybrid_group),
            apply_command: format!("kubectl apply -f istio-pqc-filter.yaml -n {}", config.namespace),
            rollback_command: format!("kubectl delete envoyfilter {} -n {}", config.name, config.namespace),
            verification_probe_command: "pqcanary probe-tls <ingress-ip>:443".to_string(),
        }
    }

    fn generate_traefik(config: &K8sMeshConfig) -> K8sMeshRemediation {
        let yaml = format!(
r#"apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: {}
  namespace: {}
  labels:
    app.kubernetes.io/managed-by: pqcanary
spec:
  minVersion: VersionTLS13
  curvePreferences:
    - {}
    - X25519
    - CurveP256
  cipherSuites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
  preferServerCipherSuites: true
"#,
            config.name, config.namespace, config.hybrid_group
        );

        K8sMeshRemediation {
            platform: K8sIngressPlatform::TraefikTLSOption,
            manifest_yaml: yaml,
            summary: format!("Traefik TLSOption resource prioritizing {} curve negotiation.", config.hybrid_group),
            apply_command: format!("kubectl apply -f traefik-pqc-tls.yaml -n {}", config.namespace),
            rollback_command: format!("kubectl delete tlsoption {} -n {}", config.name, config.namespace),
            verification_probe_command: "pqcanary probe-tls <ingress-ip>:443".to_string(),
        }
    }

    fn generate_nginx(config: &K8sMeshConfig) -> K8sMeshRemediation {
        let yaml = format!(
r#"apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {}
  namespace: {}
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ecdh-curve: "{}:X25519:secp256r1"
    nginx.ingress.kubernetes.io/ssl-ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers: "true"
spec:
  ingressClassName: nginx
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app-service
                port:
                  number: 80
"#,
            config.name, config.namespace, config.hybrid_group
        );

        K8sMeshRemediation {
            platform: K8sIngressPlatform::NginxIngress,
            manifest_yaml: yaml,
            summary: format!("NGINX Ingress annotations enforcing {} with TLS 1.3 strict ciphers.", config.hybrid_group),
            apply_command: format!("kubectl apply -f nginx-pqc-ingress.yaml -n {}", config.namespace),
            rollback_command: format!("kubectl delete ingress {} -n {}", config.name, config.namespace),
            verification_probe_command: "pqcanary probe-tls api.example.com:443".to_string(),
        }
    }

    fn generate_gateway_api(config: &K8sMeshConfig) -> K8sMeshRemediation {
        let yaml = format!(
r#"apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: {}
  namespace: {}
  labels:
    security.pqcanary.pages.dev/quantum-ready: "true"
spec:
  gatewayClassName: istio
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: default-cert
        options:
          tls.minVersion: "1.3"
          tls.curves: "{},X25519"
"#,
            config.name, config.namespace, config.hybrid_group
        );

        K8sMeshRemediation {
            platform: K8sIngressPlatform::GatewayApi,
            manifest_yaml: yaml,
            summary: format!("Kubernetes Gateway API v1 manifest configuring {} listener curves.", config.hybrid_group),
            apply_command: format!("kubectl apply -f gateway-pqc.yaml -n {}", config.namespace),
            rollback_command: format!("kubectl delete gateway {} -n {}", config.name, config.namespace),
            verification_probe_command: "pqcanary probe-tls <gateway-ip>:443".to_string(),
        }
    }

    pub fn format_markdown(rem: &K8sMeshRemediation) -> String {
        let mut out = String::new();
        out.push_str("# Kubernetes Post-Quantum Ingress Auto-Remediation\n\n");
        out.push_str(&format!("* **Target Platform:** {:?}\n", rem.platform));
        out.push_str(&format!("* **Summary:** {}\n\n", rem.summary));
        out.push_str("### Generated Manifest\n\n```yaml\n");
        out.push_str(&rem.manifest_yaml);
        out.push_str("```\n\n");
        out.push_str("### Deployment Instructions\n\n");
        out.push_str(&format!("1. **Apply Manifest:**\n   ```bash\n   {}\n   ```\n\n", rem.apply_command));
        out.push_str(&format!("2. **Verify Wire Negotiation:**\n   ```bash\n   {}\n   ```\n\n", rem.verification_probe_command));
        out.push_str(&format!("3. **Instant Rollback (If needed):**\n   ```bash\n   {}\n   ```\n", rem.rollback_command));
        out
    }
}
