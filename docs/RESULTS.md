# PQC-APS :: Experimental Evaluation & Benchmark Results

> **Automated Verification Notice**: This document is generated entirely by `scripts/generate-docs.ps1` from live evaluation artifacts in `data/*.json`. Every metric corresponds to genuine execution output without manual estimation.

## 1. Test Summary

Source: `data/test-summary.json`, generated 2026-11-24T14:24:02Z

| Metric | Value | Caption / Scope |
| :--- | :--- | :--- |
| **Total Reactor Tests** | 192 | Across 10 modules |
| **Passed** | 192 | 192/192 passing (100%) |
| **Failures** | 0 | - |
| **Errors** | 0 | - |
| **Skipped** | 0 | - |
| **Modules Evaluated** | 10 | Across reactor parent & 10 submodules |

## 2. 15-Cell Security & Attack Evaluation Matrix

Source: `data/attack-results.json`, generated 2026-11-24T15:28:08Z

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
| Downgrade | CLASSICAL-HARDENED | BLOCKED | YES | `2c7a3124-674f-4c21-be20-5df27856f0fc` | ClientHello suites stripped -> signature verification over transcript failed, suite tampering blocked |
| Downgrade | HYBRID | BLOCKED | YES | `5ab76443-adaf-4c93-8cbf-cda0b2792ce1` | Server policy (rejectClassical=true) rejected classical-only suite; signed transcript check (rejectClassical=false) detected ML-DSA-65 signature mismatch |
| MITM | CLASSICAL-VULNERABLE | SUCCEEDED | NO | none | Rogue server presented untrusted RSA key -> accepted by vulnerable client with key pinning disabled |
| MITM | CLASSICAL-HARDENED | BLOCKED | YES | `59695d51-230e-4bc1-903a-c7e31efb758a` | Rogue server presented untrusted RSA key -> pinned key check failed, rogue server rejected |
| MITM | HYBRID | BLOCKED | YES | `fd5453f0-b708-4d7a-822f-70be44a7ef19` | Rogue server presented unpinned ML-DSA-65 key -> signature verification against pinned key failed |
| Replay | CLASSICAL-VULNERABLE | SUCCEEDED | NO | none | Record seq=0 re-sent -> accepted duplicate record by vulnerable channel without sequence validation |
| Replay | CLASSICAL-HARDENED | BLOCKED | YES | `abceb7e3-aad1-46cc-8cb1-2e9af00b041a` | Record seq=0 re-sent -> rejected duplicate sequence number by ReplayGuard |
| Replay | HYBRID | BLOCKED | YES | `9b769250-6643-4b59-8f96-dc84db3b1a89` | Record seq=0 re-sent -> rejected by ReplayGuard |
| Nonce Reuse | CLASSICAL-VULNERABLE | SUCCEEDED | NO | none | Two plaintexts encrypted under same nonce=0 -> keystream reused, C1^C2 leaked P1^P2 |
| Nonce Reuse | CLASSICAL-HARDENED | BLOCKED | YES | `b3d89ad6-271e-4d26-a94e-bdb08b1b93a4` | Attempted nonce counter reset -> reset refused by NonceGuard |
| Nonce Reuse | HYBRID | BLOCKED | YES | `02964228-8741-4173-bce0-1647c76d6c49` | Duplicate nonce presented -> blocked by NonceManager |
| Tampering | CLASSICAL-VULNERABLE | UNDETECTED | NO | none | Attacker flipped bit in ciphertext -> GCM decryption threw raw exception with zero detection telemetry logged (error oracle risk; UNDETECTED tampering) |
| Tampering | CLASSICAL-HARDENED | BLOCKED | YES | `95d95fcb-3962-48d1-a509-a1370767b960` | Ciphertext bit flipped -> TamperGuard caught tag mismatch |
| Tampering | HYBRID | BLOCKED | YES | `6cb0358d-b1a9-41c5-98b2-967dcc3d0523` | ML-KEM ciphertext bit flipped -> Finished verification failed via implicit rejection |

## 3. Wire Sizes per Suite

Source: `data/benchmark-results.json`, generated 2026-11-24T15:22:59.210527800Z

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

Source: `data/benchmark-results.json`, generated 2026-11-24T15:22:59.210527800Z

| Primitive / Item | Standard / Algorithm | Raw Size | Encoded Size | Overhead / Encoding Scheme |
| :--- | :--- | :--- | :--- | :--- |
| **X25519 Public Key** | CLASSICAL | 32 B | 44 B | Raw Curve25519 point vs DER SubjectPublicKeyInfo |
| **ML-KEM-768 Encapsulation Key** | HYBRID/PQ | 1184 B | 1206 B | NIST FIPS 203 encapsulation key |
| **ML-KEM-768 Ciphertext** | HYBRID/PQ | 1088 B | 1088 B | NIST FIPS 203 KEM ciphertext |
| **ML-DSA-65 Public Key** | HYBRID/PQ | 1952 B | 1974 B | NIST FIPS 204 verification key |
| **ML-DSA-65 Signature** | HYBRID/PQ | 3309 B | 3309 B | NIST FIPS 204 signature |
| **RSA-2048 Signature** | CLASSICAL | 256 B | 256 B | PKCS#1 v1.5 RSA-2048 signature |

## 5. Latency, CPU Time, and AES-GCM Throughput

Source: `data/benchmark-results.json`, generated 2026-11-24T15:22:59.210527800Z

- **Benchmark Execution Mode**: **quick (indicative)**
- **Host Environment**: Windows 11 (amd64), JDK 21.0.10 (Oracle Corporation), 16 CPU cores

### Cryptographic Operation Latency

| Operation | Algorithm / Target | Average (µs) | p95 (µs) |
| :--- | :--- | :--- | :--- |
| keygen | **X25519** | 284.04 µs | 390.00 µs |
| keygen | **ML-KEM-768** | 366.24 µs | 564.10 µs |
| keygen | **ML-DSA-65** | 393.78 µs | 511.90 µs |
| keygen | **RSA-2048** | 67,780.24 µs | 1,92,092.20 µs |
| encapsulate | **ML-KEM-768** | 175.89 µs | 366.30 µs |
| decapsulate | **ML-KEM-768** | 159.32 µs | 349.10 µs |
| sign | **RSA-2048** | 774.92 µs | 876.60 µs |
| verify | **RSA-2048** | 52.14 µs | 132.00 µs |
| sign | **ML-DSA-65** | 547.89 µs | 641.30 µs |
| verify | **ML-DSA-65** | 228.66 µs | 367.80 µs |
| handshake | **CLASSICAL** | 1,352.33 µs | 1,639.80 µs |
| handshake | **HYBRID** | 1,502.10 µs | 2,200.30 µs |
| handshake | **PQ_ONLY** | 799.93 µs | 1,409.90 µs |

### Handshake CPU Impact

| Suite | Average Handshake CPU Time (µs) | Overhead vs CLASSICAL | Measurement Mechanism / Caveat |
| :--- | :--- | :--- | :--- |
| **CLASSICAL** | 1,250.00 µs | Baseline (1.00x) | ThreadMXBean.getCurrentThreadCpuTime() measurement: resolution depends on host OS thread scheduler (typically 10-15ms on Windows, sub-microsecond on Linux); includes thread scheduling noise and any thread-local JVM GC/JIT execution occurring during sampling. |
| **HYBRID** | 1,250.00 µs | Baseline (1.00x) | ThreadMXBean.getCurrentThreadCpuTime() measurement: resolution depends on host OS thread scheduler (typically 10-15ms on Windows, sub-microsecond on Linux); includes thread scheduling noise and any thread-local JVM GC/JIT execution occurring during sampling. |
| **PQ_ONLY** | 781.25 µs | -468.75 µs (0.63x) | ThreadMXBean.getCurrentThreadCpuTime() measurement: resolution depends on host OS thread scheduler (typically 10-15ms on Windows, sub-microsecond on Linux); includes thread scheduling noise and any thread-local JVM GC/JIT execution occurring during sampling. |

### AES-256-GCM Record Throughput

| Record Size | Operation | Throughput (MB/s) | StdDev (MB/s) | Benchmark Configuration |
| :--- | :--- | :--- | :--- | :--- |
| 1 KB | Encrypt | **40.1 MB/s** | ± 3.4 MB/s | 1 fork(s), 5 iteration(s) |
| 1 KB | Decrypt | **96.7 MB/s** | ± 4.4 MB/s | 1 fork(s), 5 iteration(s) |
| 64 KB | Encrypt | **1,903.9 MB/s** | ± 770.3 MB/s | 1 fork(s), 5 iteration(s) |
| 64 KB | Decrypt | **1,927.3 MB/s** | ± 474.0 MB/s | 1 fork(s), 5 iteration(s) |

## 6. Static Crypto Scanner Target Comparison

Source: `data/scan-report-*.json`, generated timestamps per target below

| Target Identifier | Scope / Description | Findings | Critical | High | Med | Low | Info | Score | Grade | Quantum Readiness | Source File & Timestamp |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **vulnerable-app** | samples/vulnerable-app (Legacy Baseline) | 16 | 9 | 5 | 0 | 0 | 2 | 99 | **F** | **0.0%** | `scan-report-vulnerable.json` (2026-11-24T15:23:02.827672Z) |
| **migrated-app** | samples/migrated-app (PQC Refactored) | 2 | 0 | 0 | 0 | 0 | 2 | 0 | **A** | **100.0%** | `scan-report-migrated.json` (2026-11-24T15:23:02.842659100Z) |
| **self** | Repository Root (All Modules) | 20 | 3 | 4 | 0 | 0 | 13 | 85 | **F** | **76.5%** | `scan-report-self.json` (2026-11-24T15:23:03.039733500Z) |
| **self-production** | Self Production Code (Excl. Lab & Baseline) | 13 | 0 | 0 | 0 | 0 | 13 | 0 | **A** | **100.0%** | `scan-report-self-production.json` (2026-11-24T15:23:03.135705100Z) |
| **self-tests** | Self Test Suites & Test Fixtures | 61 | 15 | 14 | 0 | 0 | 32 | 100 | **F** | **73.2%** | `scan-report-self-tests.json` (2026-11-24T15:23:03.327872500Z) |

---
*End of automated report generated by `scripts/generate-docs.ps1`.*

