# PQC-APS :: Experimental Evaluation & Benchmark Results

> **Automated Verification Notice**: This document is generated entirely by `scripts/generate-docs.ps1` from live evaluation artifacts in `data/*.json`. Every metric corresponds to genuine execution output without manual estimation.

## 1. Test Summary

Source: `data/test-summary.json`, generated 2026-11-25T17:40:37Z

| Metric | Value | Caption / Scope |
| :--- | :--- | :--- |
| **Total Reactor Tests** | 220 | Across 10 modules |
| **Passed** | 220 | 220/220 passing (100%) |
| **Failures** | 0 | - |
| **Errors** | 0 | - |
| **Skipped** | 0 | - |
| **Modules Evaluated** | 10 | Across reactor parent & 10 submodules |

## 2. 15-Cell Security & Attack Evaluation Matrix

Source: `data/attack-results.json`, generated 2026-11-25T17:40:17Z

### Matrix Overview (Attack vs Security Mode)

| Attack Vector | CLASSICAL-VULNERABLE | CLASSICAL-HARDENED | HYBRID |
| :--- | :--- | :--- | :--- |
| **Downgrade** | ❌ SUCCEEDED (Vulnerable) | ✔ BLOCKED (Defended) | ✔ BLOCKED (Defended) |
| **MITM** | ❌ SUCCEEDED (Vulnerable) | ✔ BLOCKED (Defended) | ✔ BLOCKED (Defended) |
| **Replay** | ❌ SUCCEEDED (Vulnerable) | ✔ BLOCKED (Defended) | ✔ BLOCKED (Defended) |
| **Nonce Reuse** | ❌ SUCCEEDED (Vulnerable) | ✔ BLOCKED (Defended) | ✔ BLOCKED (Defended) |
| **Tampering** | ⚠ UNDETECTED (Decryption failure, 0 telemetry) | ✔ BLOCKED (Defended) | ✔ BLOCKED (Defended) |

### Detailed Cell Evidence & Defensive Telemetry

| Attack | Mode | Outcome | Guard Triggered | Event ID | Evidence / Diagnostic Detail |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Downgrade | CLASSICAL-VULNERABLE | SUCCEEDED | NO | none | ClientHello suites [HYBRID, CLASSICAL] stripped to [CLASSICAL] -> accepted by vulnerable server without detection |
| Downgrade | CLASSICAL-HARDENED | BLOCKED | YES | `181c1879-d1f8-4049-a505-edc5c9d321a0` | ClientHello suites stripped -> signature verification over transcript failed, suite tampering blocked |
| Downgrade | HYBRID | BLOCKED | YES | `c6083a2c-8bac-4d91-a119-8c14c6ed6016` | Server policy (rejectClassical=true) rejected classical-only suite; signed transcript check (rejectClassical=false) detected ML-DSA-65 signature mismatch |
| MITM | CLASSICAL-VULNERABLE | SUCCEEDED | NO | none | Rogue server presented untrusted RSA key -> accepted by vulnerable client with key pinning disabled |
| MITM | CLASSICAL-HARDENED | BLOCKED | YES | `c0b20839-c06c-44ba-a677-ababc2f20435` | Rogue server presented untrusted RSA key -> pinned key check failed, rogue server rejected |
| MITM | HYBRID | BLOCKED | YES | `73539a08-b6a5-483f-9eda-2698b3af8e0a` | Rogue server presented unpinned ML-DSA-65 key -> signature verification against pinned key failed |
| Replay | CLASSICAL-VULNERABLE | SUCCEEDED | NO | none | Record seq=0 re-sent -> accepted duplicate record by vulnerable channel without sequence validation |
| Replay | CLASSICAL-HARDENED | BLOCKED | YES | `f445b3e4-6666-4bf3-bfaa-bcc95d6920de` | Record seq=0 re-sent -> rejected duplicate sequence number by ReplayGuard |
| Replay | HYBRID | BLOCKED | YES | `7f26b9c2-721a-4dbe-8d17-5e250a55c14f` | Record seq=0 re-sent -> rejected by ReplayGuard |
| Nonce Reuse | CLASSICAL-VULNERABLE | SUCCEEDED | NO | none | Two plaintexts encrypted under same nonce=0 -> keystream reused, C1^C2 leaked P1^P2 |
| Nonce Reuse | CLASSICAL-HARDENED | BLOCKED | YES | `84c5251c-7da8-45a4-abc3-cc76daaaf4d2` | Attempted nonce counter reset -> reset refused by NonceGuard |
| Nonce Reuse | HYBRID | BLOCKED | YES | `940047ce-3ed1-457a-ab74-b7f293ef1cd0` | Duplicate nonce presented -> blocked by NonceManager |
| Tampering | CLASSICAL-VULNERABLE | UNDETECTED | NO | none | Attacker flipped bit in ciphertext -> GCM decryption threw raw exception with zero detection telemetry logged (no detection telemetry; UNDETECTED tampering) |
| Tampering | CLASSICAL-HARDENED | BLOCKED | YES | `8c78dd24-515a-45ce-8cb5-f5b4d1869d10` | Ciphertext bit flipped -> TamperGuard caught tag mismatch |
| Tampering | HYBRID | BLOCKED | YES | `34edb09d-d6f4-4853-9d68-bbd6c6f35b1d` | ML-KEM ciphertext bit flipped -> Finished verification failed via implicit rejection |

## 3. Wire Sizes per Suite

Source: `data/benchmark-results.json`, generated 2026-11-25T17:40:24.981357Z

> *Note*: Wire sizes represent serialized prototype bytes via `ObjectOutputStream` framing, not real TLS 1.3 records.

| Handshake Message / Stage | CLASSICAL (Bytes) | HYBRID (Bytes) | PQ_ONLY (Bytes) | Notes / Observations |
| :--- | :--- | :--- | :--- | :--- |
| **ClientHello** | 111 B | 1356 B | 1311 B | X25519 pk + ML-KEM-768 pk + nonce + suites |
| **ServerHello** | 390 B | 4488 B | 4444 B | X25519 pk + ML-KEM ct + ML-DSA-65 sig + nonce |
| **Finished (x2)** | 0 B | 254 B | 254 B | Mutual Finished messages (Client + Server) |
| **Unframed Key Material (Payload)** | 501 B | 6098 B | 6009 B | Raw primitive keys, ciphertext & signatures |
| **Total Handshake Wire** | **820 B** | **6433 B** | **6344 B** | Complete serialized wire socket transmission |

- **HYBRID / CLASSICAL Handshake Wire Ratio**: **7.85x** (6433 B vs 820 B, serialized prototype bytes, not real TLS bytes)
- **HYBRID / CLASSICAL Key Material Ratio**: **12.17x** (6098 B vs 501 B)

## 4. Cryptographic Key and Signature Sizes

Source: `data/benchmark-results.json`, generated 2026-11-25T17:40:24.981357Z

| Primitive / Item | Standard / Algorithm | Raw Size | Encoded Size | Overhead / Encoding Scheme |
| :--- | :--- | :--- | :--- | :--- |
| **X25519 Public Key** | CLASSICAL | 32 B | 44 B | Raw Curve25519 point vs DER SubjectPublicKeyInfo |
| **ML-KEM-768 Encapsulation Key** | HYBRID/PQ | 1184 B | 1206 B | NIST FIPS 203 encapsulation key |
| **ML-KEM-768 Ciphertext** | HYBRID/PQ | 1088 B | 1088 B | NIST FIPS 203 KEM ciphertext |
| **ML-DSA-65 Public Key** | HYBRID/PQ | 1952 B | 1974 B | NIST FIPS 204 verification key |
| **ML-DSA-65 Signature** | HYBRID/PQ | 3309 B | 3309 B | NIST FIPS 204 signature |
| **RSA-2048 Signature** | CLASSICAL | 256 B | 256 B | PKCS#1 v1.5 RSA-2048 signature |

## 5. Latency, CPU Time, and AES-GCM Throughput

Source: `data/benchmark-results.json`, generated 2026-11-25T17:40:24.981357Z

- **Benchmark Execution Mode**: **quick (indicative)**
- **Host Environment**: Windows 11 (amd64), JDK 21.0.10 (Oracle Corporation), 16 CPU cores

### Cryptographic Operation Latency

| Operation | Algorithm / Target | Average (µs) | p95 (µs) |
| :--- | :--- | :--- | :--- |
| keygen | **X25519** | 511.85 µs | 798.10 µs |
| keygen | **ML-KEM-768** | 301.23 µs | 424.60 µs |
| keygen | **ML-DSA-65** | 623.91 µs | 891.80 µs |
| keygen | **RSA-2048** | 66,212.19 µs | 1,50,661.00 µs |
| encapsulate | **ML-KEM-768** | 284.07 µs | 517.40 µs |
| decapsulate | **ML-KEM-768** | 246.30 µs | 454.80 µs |
| sign | **RSA-2048** | 798.02 µs | 944.10 µs |
| verify | **RSA-2048** | 48.86 µs | 71.10 µs |
| sign | **ML-DSA-65** | 345.77 µs | 482.00 µs |
| verify | **ML-DSA-65** | 204.38 µs | 400.90 µs |
| handshake | **CLASSICAL** | 1,511.87 µs | 1,888.20 µs |
| handshake | **HYBRID** | 12,028.42 µs | 33,008.20 µs |
| handshake | **PQ_ONLY** | 5,214.48 µs | 9,776.30 µs |

### Handshake CPU Impact

| Suite | Average Handshake CPU Time (µs) | Overhead vs CLASSICAL | Measurement Mechanism / Caveat |
| :--- | :--- | :--- | :--- |
| **CLASSICAL** | 4,062.50 µs | Baseline (1.00x) | ThreadMXBean.getCurrentThreadCpuTime() measurement: resolution depends on host OS thread scheduler (typically 10-15ms on Windows, sub-microsecond on Linux); includes thread scheduling noise and any thread-local JVM GC/JIT execution occurring during sampling. |
| **HYBRID** | 4,062.50 µs | Baseline (1.00x) | ThreadMXBean.getCurrentThreadCpuTime() measurement: resolution depends on host OS thread scheduler (typically 10-15ms on Windows, sub-microsecond on Linux); includes thread scheduling noise and any thread-local JVM GC/JIT execution occurring during sampling. |
| **PQ_ONLY** | 2,656.25 µs | -1,406.25 µs (0.65x) | ThreadMXBean.getCurrentThreadCpuTime() measurement: resolution depends on host OS thread scheduler (typically 10-15ms on Windows, sub-microsecond on Linux); includes thread scheduling noise and any thread-local JVM GC/JIT execution occurring during sampling. |

### AES-256-GCM Record Throughput

| Record Size | Operation | Throughput (MB/s) | StdDev (MB/s) | Benchmark Configuration |
| :--- | :--- | :--- | :--- | :--- |
| 1 KB | Encrypt | **12.5 MB/s** | ± 5.6 MB/s | 1 fork(s), 5 iteration(s) |
| 1 KB | Decrypt | **16.0 MB/s** | ± 9.6 MB/s | 1 fork(s), 5 iteration(s) |
| 64 KB | Encrypt | **170.3 MB/s** | ± 112.6 MB/s | 1 fork(s), 5 iteration(s) |
| 64 KB | Decrypt | **346.2 MB/s** | ± 274.1 MB/s | 1 fork(s), 5 iteration(s) |

## 6. Static Crypto Scanner Target Comparison

Source: `data/scan-report-*.json`, generated timestamps per target below

| Target Identifier | Scope / Description | Findings | Critical | High | Med | Low | Info | Score | Grade | Quantum Readiness | Source File & Timestamp |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **vulnerable-app** | samples/vulnerable-app (Legacy Baseline) | 16 | 9 | 5 | 0 | 0 | 2 | 99 | **F** | **0.0%** | `scan-report-vulnerable.json` (2026-11-25T17:40:21.148588900Z) |
| **migrated-app** | samples/migrated-app (PQC Refactored) | 2 | 0 | 0 | 0 | 0 | 2 | 0 | **A** | **100.0%** | `scan-report-migrated.json` (2026-11-25T17:40:21.845933600Z) |
| **self** | Repository Root (All Modules) | 20 | 3 | 4 | 0 | 0 | 13 | 85 | **F** | **76.5%** | `scan-report-self.json` (2026-11-25T17:40:22.600997500Z) |
| **self-production** | Self Production Code (Excl. Lab & Baseline) | 13 | 0 | 0 | 0 | 0 | 13 | 0 | **A** | **100.0%** | `scan-report-self-production.json` (2026-11-25T17:40:23.343151500Z) |
| **self-tests** | Self Test Suites & Test Fixtures | 61 | 15 | 14 | 0 | 0 | 32 | 100 | **F** | **73.2%** | `scan-report-self-tests.json` (2026-11-25T17:40:24.182812400Z) |

---
*End of automated report generated by `scripts/generate-docs.ps1`.*

