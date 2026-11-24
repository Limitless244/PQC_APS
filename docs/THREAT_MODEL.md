# PQC-APS Threat Model

This document outlines the security architecture, protected assets, attacker capabilities, defensive guard mechanisms, trust assumptions, and explicit non-goals for the Post-Quantum Cryptographic Attack Prevention System (PQC-APS).

---

## 1. Protected Assets

1. **Application Payload Confidentiality**: Ensuring that application messages transmitted across the socket remain confidential against both present-day eavesdroppers and future quantum adversaries.
2. **Message Integrity & Authenticity**: Guaranteeing that data in transit cannot be modified, injected, reordered, or truncated without immediate cryptographic detection.
3. **Session Key Confidentiality**: Preventing passive or active adversaries from recovering the ephemeral symmetric session keys derived during key exchange.
4. **Peer Identity Authenticity**: Verifying the genuine cryptographic identity of the remote server to prevent impersonation and on-path interception.
5. **Negotiation Integrity**: Ensuring that cipher suite selection reflects the mutual highest-security capabilities of both client and server without downgrade interference.

---

## 2. Attacker Capabilities & Threat Profiles

The security model assumes adversaries with the following capabilities:

### A. Passive Network Eavesdropper
- **Capabilities**: Can observe, record, and archive all network traffic transmitted over the TCP socket without altering message contents.
- **Harvest-Now-Decrypt-Later (HNDL)**: The adversary stores encrypted sessions today with the goal of decrypting them in the future using a Cryptanalytically Relevant Quantum Computer (CRQC).

### B. Active On-Path Network Attacker (Dolev-Yao Model)
- **Capabilities**: Controls the communication channel. Can intercept, modify, drop, inject, delay, and replay arbitrary network packets.
- **Proxy Capabilities**: Can act as a Man-in-the-Middle (MITM), terminating independent connections with client and server unless prevented by cryptographic authentication.

### C. Future Quantum Adversary
- **Shor's Algorithm**: Capable of computing discrete logarithms on elliptic curves (breaking Curve25519/ECDH) and factoring large composite integers (breaking RSA-2048 in polynomial time).
- **Grover's Algorithm**: Provides quadratic speedup against symmetric primitives; mitigated by retaining 256-bit symmetric keys (AES-256-GCM), providing $\ge 128$ bits of post-quantum security margin.

---

## 3. Trust Assumptions

1. **Initial Trust Root**: The client is provisioned with an authentic out-of-band pinned public key of the server (ML-DSA-65 or RSA-2048) prior to initiating the handshake.
2. **Endpoint Platform Security**: Client and server host operating systems, JVM execution environments, and hardware are assumed trusted and uncompromised (malware-free).
3. **CSPRNG Integrity**: The underlying platform provides a cryptographically secure pseudo-random number generator (`java.security.SecureRandom`) backed by sufficient operating system entropy.
4. **Implementation Correctness of Primitives**: The underlying mathematical primitives (FIPS 203 ML-KEM, FIPS 204 ML-DSA, RFC 7748 X25519, NIST SP 800-38D AES-GCM) provided by Bouncy Castle 1.80 and JDK 21 are assumed algorithmically correct.

---

## 4. The 8 Defensive Guards

The `attack-engine` module provides eight distinct defensive guards protecting against the full spectrum of protocol and implementation attacks:

| Threat / Attack Vector | Attack Mechanism | Defensive Mitigation | Guard Class | Test Verification | Event Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Downgrade Attack (VULN-1)** | Stripping high-security suites (`HYBRID`) from ClientHello to force legacy cipher suites. | Full handshake transcript including client-offered suites is cryptographically bound into the digital signature. | `DowngradeGuard` | `DowngradeGuardTest`, `DowngradeAttackTest` | `DOWNGRADE` |
| **Man-in-the-Middle (VULN-4)** | Rogue server injects unpinned public key to terminate two independent connection legs. | Strict public key pinning with fail-closed enforcement; rejects unpinned keys immediately. | `MitmGuard` | `MitmGuardTest`, `MitmAttackTest` | `MITM` |
| **Message Replay (VULN-2)** | Capturing authentic ciphertext records and re-injecting them into the TCP socket. | Strict 64-bit monotonic sequence numbers and sliding-window replay filter. | `ReplayGuard` | `ReplayGuardTest`, `ReplayAttackTest` | `REPLAY` |
| **Nonce Reuse (VULN-3)** | Encrypting multiple records with identical 96-bit AES-GCM nonces, destroying GHASH authenticity. | Monotonic atomic counter tracking, duplicate nonce rejection, and mandatory rekeying before counter exhaustion. | `NonceManager` | `NonceManagerTest`, `NonceReuseAttackTest` | `NONCE_REUSE` |
| **Ciphertext Tampering** | Bit-flipping attacks on ciphertext records or handshake Finished verification data. | AES-256-GCM authentication tag check combined with dual-direction HMAC-SHA256 Finished confirmation. | `TamperGuard` | `TamperGuardTest`, `HardenedAttackMatrixTest` | `TAMPER` |
| **Static Key Reuse** | Reusing ephemeral Diffie-Hellman or KEM keypairs across distinct sessions, compromising forward secrecy. | Ephemeral public key fingerprint cache rejecting keypair reuse across session lifecycles. | `KeyReuseGuard` | `KeyReuseGuardTest` | `KEY_REUSE` |
| **Weak Randomness / PRNG Bias** | Low-entropy or predictable nonces leading to key extraction and keystream correlation. | Heuristic entropy estimation and NIST SP 800-22 mono-bit statistical frequency checks on generated nonces. | `RandomnessGuard` | `RandomnessGuardTest` | `RANDOMNESS_FAIL` |
| **Timing Side-Channel** | Exploiting variable-time string/array comparisons to recover signatures or authentication tags. | Constant-time array comparison (`MessageDigest.isEqual`) preventing timing oracles. | `TimingGuard` | `TimingGuardTest` | `TIMING_LEAK` |

---

## 5. Explicit Out-of-Scope Security Boundaries

To maintain rigorous scientific scope, the following threats are explicitly outside the design goals of this prototype:

1. **Endpoint Compromise & Memory Forensics**: If an attacker has root privileges, malware, or debugger access to inspect the JVM memory space or extract private keys from RAM, endpoint security is forfeit.
2. **Hardware Side-Channels**: Physical microarchitectural attacks (differential power analysis, electromagnetic radiation, Rowhammer, Spectre/Meltdown cache attacks) are not addressed beyond software constant-time comparison in `TimingGuard`.
3. **Traffic Analysis & Metadata Privacy**: Packet sizing, timing jitter, flow frequencies, and IP/port metadata remain visible on the wire. Packet padding or Tor-like onion routing is out of scope.
4. **Real TLS 1.3 Wire Compatibility**: The system prototypes post-quantum key exchange mechanisms over Java socket object streams (`ObjectOutputStream`), not RFC 8446 byte-exact TLS 1.3 records.
5. **WebPKI & Certificate Governance**: Public key validation relies on pinned public keys rather than X.509 certificate chains, Certificate Authorities (CAs), Certificate Revocation Lists (CRLs), or OCSP stapling.
