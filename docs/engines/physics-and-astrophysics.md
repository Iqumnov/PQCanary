# Relativistic Causality and Pulsar Synchronization Engine

This document specifies the astrophysical timing verifications, WGS-84 Vincenty geodesic calculations, optical fiber light-cone bounds, and biological computing models in PQCanary.

---

## 1. Relativistic Light-Cone Causality Verification

In distributed cryptographic networks, adversaries can forge timestamps or deploy man-in-the-middle (MITM) proxies that claim distant geographical locations. PQCanary enforces physical light-cone bounds derived from special relativity to detect impossible latencies and proxy impersonation.

### 1.1. Physical Constants and Propagation Velocity
- Speed of light in vacuum: $c = 299,792.458 \text{ km/s}$.
- Typical refractive index of silica optical fiber: $n_{\text{silica}} = 1.4682$.
- Effective propagation speed of light in terrestrial fiber:

$$v_{\text{fiber}} = \frac{c}{n_{\text{silica}}} \approx 204,190.477 \text{ km/s}$$

### 1.2. WGS-84 Geodesic Distance (Vincenty Formula)
To determine the true physical separation between two geographic coordinates $(\phi_1, L_1)$ and $(\phi_2, L_2)$, PQCanary implements Vincenty's inverse geodesic formula on the WGS-84 reference ellipsoid ($a = 6,378,137.0 \text{ m}$, $f = 1/298.257223563$).

The minimal theoretical round-trip time (RTT) across optical fiber is:

$$\text{RTT}_{\text{min}} = \frac{2 \cdot d_{\text{Vincenty}}}{v_{\text{fiber}}}$$

### 1.3. Causality Violations
If an active network probe measures a network RTT significantly lower than $\text{RTT}_{\text{min}}$, a relativistic causality violation is flagged:
- The remote endpoint is spoofing its physical geolocation coordinates.
- An intermediate caching proxy or CDN edge node is terminating handshakes without forwarding traffic to the origin.

---

## 2. Cosmic Pulsar Clock Synchronization

Standard network time synchronization protocols (NTP, PTP, and GPS time) are vulnerable to spoofing, clock skew attacks, and leap-second ambiguities.

PQCanary's `PulsarClock` module integrates rotational timing metrics derived from millisecond radio pulsars cataloged by the Australia Telescope National Facility (ATNF):

| Pulsar Identifier | Rotational Period ($P$) | Spin Down Rate ($\dot{P}$) | Stability Class |
| :--- | :--- | :--- | :--- |
| **PSR J0437-4715** | $5.75745193 \text{ ms}$ | $5.73 \times 10^{-20} \text{ s/s}$ | Extreme (Comparable to atomic clocks) |
| **PSR J1713+0747** | $4.57013653 \text{ ms}$ | $8.53 \times 10^{-21} \text{ s/s}$ | High-Precision Timing Array |
| **PSR B1937+21** | $1.55780645 \text{ ms}$ | $1.05 \times 10^{-19} \text{ s/s}$ | Ultra-Fast Millisecond Standard |

### Pulsar Verification Mechanism
When auditing long-lived digital certificates or cryptographic timestamping authorities:
1. The pulse count since a baseline astrophysical epoch is verified against relativistic barycentric arrival times.
2. If the certificate validity window or server timestamp diverges from cosmic pulsar time drift by more than allowable tolerances, a timestamp vulnerability is logged.

---

## 3. Biological and Quantum Decoherence Modeling

PQCanary extends cryptographic validation to bio-molecular computing and physical quantum systems:

### 3.1. DNA Cryptography (SantaLucia Nearest-Neighbor Model)
Evaluates nucleotide-based encryption keys against thermodynamic strand melting temperatures ($T_m$) using the SantaLucia 1998 nearest-neighbor enthalpy ($\Delta H$) and entropy ($\Delta S$) parameters:

$$T_m = \frac{\Delta H^\circ}{\Delta S^\circ + R \ln(C_{\text{total}} / 4)} - 273.15$$

Ensures synthetic DNA cryptographic keys remain physically stable under ambient physiological conditions.

### 3.2. Lindblad Master Equation Decoherence Simulation
Models the time evolution of physical qubit density matrices ($\rho(t)$) under environmental noise:

$$\frac{d\rho}{dt} = -\frac{i}{\hbar}[H, \rho] + \sum_k \left( L_k \rho L_k^\dagger - \frac{1}{2} \{L_k^\dagger L_k, \rho\} \right)$$

Calculates longitudinal relaxation ($T_1$) and transverse dephasing ($T_2$), von Neumann entropy, and state purity to predict when quantum memory states undergo decoherence.
