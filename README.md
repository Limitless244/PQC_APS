# PQC-APS — Post-Quantum Cryptography Attack Prevention System

A capstone project demonstrating the migration of a client-server communication
layer from classical cryptography to a **hybrid classical + post-quantum** scheme,
with active attack detection and prevention, and a live performance dashboard.

---

## 🏗️ Architecture

| Module | Purpose |
|--------|---------|
| `crypto-scanner` | Static analyser for vulnerable crypto patterns (RSA<3072, MD5, hardcoded keys …) |
| `hybrid-kex` | X25519 + ML-KEM-768 hybrid key exchange; HKDF-SHA256 session key derivation |
| `pq-auth` | ML-DSA-65 signatures over the full handshake transcript |
| `secure-channel` | AES-256-GCM record layer with counter nonces and sequence numbers |
| `attack-engine` | 8 attack detectors/preventers (downgrade, MITM, replay, nonce reuse, …) |
| `crypto-agility` | YAML-driven algorithm suite selection (CLASSICAL / HYBRID / PQ_ONLY) |
| `benchmark-dashboard` | JMH benchmarks + Spring Boot backend + React dashboard |

---

## ⚡ Quick Start

### Prerequisites
- **JDK 21+** (JDK 24 enables native ML-KEM/ML-DSA; JDK 21 falls back to Bouncy Castle automatically)
- **Node.js 18+** (for the dashboard frontend)
- No global Maven required — use the included `mvnw` / `mvnw.cmd` wrapper

### Build everything
```bash
# Windows
mvnw.cmd clean package -DskipTests

# macOS / Linux
./mvnw clean package -DskipTests
```

### Run all tests
```bash
mvnw.cmd verify
```

### Run the dashboard
```bash
# 1. Start the Spring Boot backend
mvnw.cmd -pl benchmark-dashboard spring-boot:run

# 2. In a second terminal, start the React frontend
cd benchmark-dashboard/frontend
npm install
npm run dev
# Open http://localhost:5173
```

---

## 🔐 Cryptographic Design

### Handshake (Hybrid)
```
Client                                          Server
  |-- xpk_c, kpk_c, suites, nonce_c ---------->|
  |                                             | ss1 = X25519(xsk_s, xpk_c)
  |                                             | (ct, ss2) = ML-KEM.Enc(kpk_c)
  |                                             | sig = ML-DSA.Sign(transcript)
  |<-- xpk_s, ct, nonce_s, suite, sig ----------|
  | verify sig ✓                                |
  | ss1 = X25519(xsk_c, xpk_s)                  |
  | ss2 = ML-KEM.Dec(ksk_c, ct)                 |
  |-- session_key = HKDF(ss1||ss2||H(transcript))|
```

### Algorithm Suites
| Suite | Key Exchange | Authentication | Symmetric |
|-------|-------------|---------------|----------|
| CLASSICAL | X25519 / RSA-2048 | ECDSA | AES-256-GCM |
| HYBRID | X25519 + ML-KEM-768 | ML-DSA-65 | AES-256-GCM |
| PQ_ONLY | ML-KEM-768 | ML-DSA-65 | AES-256-GCM |

### Attack Prevention Summary
| Attack | Prevention Mechanism |
|--------|---------------------|
| Suite Downgrade | ML-DSA signed suite list |
| MITM | Signature over full transcript (xpk_c, xpk_s, ct, nonces) |
| Replay | Nonce + timestamp + per-direction sequence numbers |
| GCM Nonce Reuse | Counter nonce manager, rekeying before overflow |
| Timing Side Channel | `MessageDigest.isEqual` constant-time comparison |
| Weak Randomness | Scanner rule + runtime `SecureRandom` guard |
| Key Reuse | Fresh ephemeral keys per session (forward secrecy) |
| Ciphertext Tampering | GCM tag verification, no oracle error messages |

---

## 📚 Technology Stack
- **Language**: Java 21 (LTS)
- **PQC Library**: Bouncy Castle 1.80 (bcprov-jdk18on, bcpkix-jdk18on)
- **Build**: Maven (via wrapper)
- **Backend**: Spring Boot 3.4.5
- **Frontend**: React + Vite + Chart.js
- **Tests**: JUnit 5 + AssertJ
- **Benchmarks**: JMH 1.37

---

## 📄 License
MIT — for educational/research use only. Do not use this code in production without
a full security audit by qualified cryptographers.
