# Active Network Probing Guide

This guide explains how to perform direct binary network probes against live TLS 1.3 and SSH 2.0 servers to evaluate post-quantum key exchange capabilities without deploying agents.

---

## 1. TLS 1.3 Post-Quantum Handshake Probing

Modern web servers and reverse proxies negotiate key exchange during the initial TLS handshake. To verify whether an endpoint is immune to Store-Now-Decrypt-Later (SNDL) harvesting, PQCanary synthesizes an active TLS 1.3 `ClientHello` offering post-quantum hybrid groups.

### 1.1. CLI Usage

```bash
pqcanary probe cloudflare.com:443
```

**JSON Output:**
```bash
pqcanary probe google.com:443 --format json
```

### 1.2. Binary Handshake Architecture

```
PQCanary                                                          Remote Server
   |                                                                    |
   | --- TCP SYN / Handshake Connect ---------------------------------> |
   | <--- TCP SYN-ACK ------------------------------------------------- |
   |                                                                    |
   | --- TLS 1.3 ClientHello -----------------------------------------> |
   |     Supported Groups:                                              |
   |       0x11ec (X25519MLKEM768 - NIST FIPS 203)                      |
   |       0x6399 (X25519Kyber768 - Draft Hybrid)                       |
   |       0x001d (X25519 - Classical ECDH)                            |
   |       0x0017 (secp256r1 - Classical NIST P-256)                    |
   |     Key Share: X25519MLKEM768 + X25519                             |
   |                                                                    |
   | <--- TLS 1.3 ServerHello ----------------------------------------- |
   |     Selected Group: 0x11ec (X25519MLKEM768)                        |
   |                                                                    |
   | [Classify: SAFE | RTT: 24 ms | Immune to Harvest-Now-Decrypt-Later]|
```

### 1.3. Interpreting TLS Probe Findings

- **SAFE (NIST FIPS 203)**: The server selected `0x11ec` (X25519MLKEM768). Session keys cannot be cracked by Shor's algorithm running on a future quantum computer.
- **HYBRID (Draft)**: The server selected `0x6399` (X25519Kyber768). Post-quantum safe today, but scheduled for migration to final FIPS 203 parameters.
- **VULNERABLE (Classical)**: The server selected `0x001d` (X25519) or `0x0017` (secp256r1) despite the client offering ML-KEM. Encrypted sessions traversing public networks can be recorded and decrypted once quantum computers arrive.

---

## 2. SSH 2.0 Post-Quantum Transport Probing

Secure Shell (SSH) connections protect developer bastion hosts, Git repositories, and automated orchestration pipelines.

### 2.1. CLI Usage

```bash
pqcanary probe-ssh github.com:22
```

### 2.2. SSH Protocol Exchange

1. **Identification Exchange**: PQCanary opens a TCP connection to port 22 and transmits `SSH-2.0-PQCanary-Probe_0.1.0`.
2. **KEXINIT Exchange**: Transmits a binary `SSH_MSG_KEXINIT` payload and parses the server's algorithm list.
3. **Algorithm Inspection**:
   - Evaluates whether the server supports post-quantum hybrid key exchange:
     - `sntrup761x25519-sha512@openssh.com` (OpenSSH default since version 9.0)
     - `mlkem768x25519-sha256`
   - Checks if the server permits obsolete, quantum-broken key exchange algorithms:
     - `diffie-hellman-group14-sha1`
     - `ecdh-sha2-nistp256`

---

## 3. Server-Side Request Forgery (SSRF) Defense

When invoking `pqcanary probe` or `pqcanary probe-ssh` in multi-tenant environments or automated CI runners, PQCanary automatically enforces SSRF protections:
- **Cloud Metadata Prohibition**: Unconditionally blocks requests targeting `169.254.169.254`, `fd00:ec2::254`, and cloud metadata endpoints.
- **Strict Network Isolation**: When `PQCANARY_STRICT_NETWORK=1` is set, requests targeting RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or loopback (`127.0.0.1`, `localhost`) are rejected.
- **DNS Rebinding Prevention**: Validates resolved IP addresses before establishing TCP sockets.
