# Thermodynamics Modeling and Hardware Side-Channel Diagnostics

This document specifies the physical modeling of Landauer thermodynamic dissipation, thermal side-channel attack (SCA) vectors, Boolean masking verification, and Differential Fault Analysis (DFA) simulations in PQCanary.

---

## 1. Landauer's Principle and Cryptographic Dissipation

Rolf Landauer demonstrated in 1961 that computation itself does not fundamentally require energy; rather, the erasure of information (irreversible logical operations) dissipates a minimum amount of thermodynamic entropy into the environment.

The fundamental Landauer limit dictates that erasing 1 bit of information at absolute temperature $T$ dissipates at least:

$$E_{\text{min}} = k_B T \ln 2$$

Where:
- $k_B = 1.380649 \times 10^{-23} \text{ J/K}$ (Boltzmann's constant).
- $T$ is temperature in Kelvin (default: $300.0 \text{ K}$ at room temperature).
- $\ln 2 \approx 0.693147$.

At room temperature ($300 \text{ K}$):

$$E_{\text{min}} \approx 2.87 \times 10^{-21} \text{ Joules} \approx 0.00287 \text{ aJ}$$

---

## 2. Thermal Side-Channel Analysis (SCA)

Conventional side-channel analysis targets electromagnetic radiation or supply current fluctuations. However, advanced adversaries can capture localized micro-calorimetric thermal gradients across silicon dies using high-resolution infrared cameras or near-field Peltier sensors.

### Thermal Vulnerability Criterion

For a cryptographic circuit executing $N_{\text{gates}}$ with $N_{\text{erased}}$ irreversible bit erasures per clock cycle:

$$\text{Dissipation} = N_{\text{erased}} \cdot k_B T \ln 2$$

PQCanary evaluates whether total thermal dissipation exceeds the sensor detectability threshold:

$$\text{Threshold} = 1.0 \text{ femtojoule} \ (1.0 \times 10^{-15} \text{ J})$$

If dissipation exceeds $1.0 \text{ fJ}$, the circuit is flagged with `vulnerable_to_sca: true`.

```
                    Circuit Gate Specification
                                |
                                v
               +----------------------------------+
               |     ThermodynamicsAnalyzer       |
               |  - Temperature (Kelvin)          |
               |  - Total Logic Gates             |
               |  - Irreversible Bit Erasures     |
               +----------------------------------+
                                |
                                v
               +----------------------------------+
               |     Landauer Dissipation Calc    |
               |    E = N_erased * k_B * T * ln2  |
               +----------------------------------+
                                |
                   +------------+------------+
                   |                         |
                   v                         v
            [E > 1.0 fJ]              [E <= 1.0 fJ]
          Thermal Side-Channel         Thermally Resilient
           Risk Detected               Circuit Boundary
```

---

## 3. Mitigation: Reversible Computing

To eliminate thermodynamic information erasure, PQCanary guides hardware designers toward reversible logic paradigms:
- **Fredkin Gate (CSWAP)**: Reversible conservative 3-bit logic gate where bit count is preserved.
- **Toffoli Gate (CCNOT)**: Universal reversible 3-bit logic gate.
- **Quantum Gates**: Pure unitary transformations ($U^\dagger U = I$) exhibiting zero theoretical information loss.

---

## 4. Hardware Fault Injection (DFA) and DPA Resiliency

In addition to thermodynamic modeling, PQCanary inspects hardware and embedded firmware implementations for physical vulnerability vectors:

### 4.1. Differential Fault Analysis (DFA)
- Simulates clock glitching, voltage dropping, and focused laser beam injection targeting round keys during AES and lattice polynomial evaluations.
- Verifies that intermediate cryptographic states are validated against parity checks before outputting ciphertexts or signatures.

### 4.2. Differential Power Analysis (DPA) and Boolean Masking
- Evaluates source code for order-$d$ Boolean masking schemes:

$$x = m \oplus r_1 \oplus r_2 \oplus \dots \oplus r_d$$

- Verifies that sensitive variables never appear in unmasked native registers during S-Box lookup operations or polynomial number-theoretic transforms (NTT).
