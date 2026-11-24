# System Limitations & Engineering Constraints

This document provides a transparent, rigorous assessment of the limitations, trade-offs, and boundary assumptions present in the PQC-APS prototype.

---

## 1. Prototype Scope vs Production Realities

### A. Chat Demo MITM Simulation vs Real Attack Lab Proxy
- **Chat Demo Limitation**: In the interactive web Chat Demo (`ChatDemoService`), in `CLASSICAL-VULNERABLE` mode, the attacker panel is handed a reference to the session keys (`attackerCompromisedKeys = this.sessionKeys`). This design simulates the real-time outcome of an eavesdropping/MITM breach within a single-threaded Spring UI session without requiring browser users to configure network proxies.
- **Genuine Attack Lab Execution**: In contrast, the real, fully functional two-leg TCP MITM attack proxy is implemented in `attack-lab` (`MitmAttackTest.java` and `SecurityMatrixRunner.java`). In the test harness, the MITM actually binds intermediate TCP sockets, terminates independent handshakes with the client and server (`[MITM PROXY]` log lines), intercepts wire records, and decrypts ciphertext using keys derived over the rogue socket connection.

### B. CLASSICAL-HARDENED vs HYBRID: The Quantum Threat Horizon
- **Attack Matrix Equivalence**: In the 15-cell evaluation matrix (`RESULTS.md`), both `CLASSICAL-HARDENED` and `HYBRID` successfully block all five network attacks (Downgrade, MITM, Replay, Nonce Reuse, and Tampering).
- **The Undetected Threat (HNDL)**: The 15-cell matrix evaluates active network attacks against present-day adversaries. It **does not and cannot measure the Harvest-Now-Decrypt-Later (HNDL)** quantum threat.
- **Why HYBRID Matters**: A classical hardened channel captured today can be decrypted post-hoc once a Cryptanalytically Relevant Quantum Computer (CRQC) breaks X25519 discrete logs. The `HYBRID` suite eliminates this threat by combining X25519 with ML-KEM-768. The cryptographic independence of the combiner is verified in `HybridKeyScheduleTest`: altering either $ss_1$ or $ss_2$ alone completely changes the derived session keys, ensuring confidentiality holds as long as ML-KEM remains secure.

### C. Prototype Framing vs RFC 8446 Wire Formats
- **Wire Overhead Context**: All wire sizes reported in benchmarks (820 B for Classical, 6,433 B for Hybrid) reflect Java object serialization (`java.io.ObjectOutputStream`) framing.
- **Not Real TLS Records**: These byte counts include Java class metadata and type headers. While they accurately reflect relative overhead (~7.85x wire size, ~12.17x key material), they do not match RFC 8446 binary record structures.

### D. Java Cryptography Environment (JDK 21 vs JDK 24+)
- **Dependency on Bouncy Castle 1.80**: Because this project targets JDK 21.0.10 LTS, Bouncy Castle is required to provide NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65).
- **Native JCE Support**: Native, vendor-optimized ML-KEM and ML-DSA implementations in the standard `java.security` provider are introduced only in JDK 24+ (via JEP 496 and JEP 497).

---

## 2. Static Code Scanner Heuristics

### A. Regex and AST Limitations
- The `crypto-scanner` operates via regex-based pattern matching and keyword heuristics over code lines, configuration files, and YAML manifests. It does not perform full inter-procedural data flow analysis or symbolic taint tracking.

### B. Snippet Redaction
- To prevent credential leaks in generated scan reports, findings display only the first 4 leading characters of matching lines followed by truncation asterisks.

### C. Meaning of "Quantum Readiness" & Target Scopes
- **Heuristic Counting**: "Quantum Readiness" measures the ratio of post-quantum algorithm references (`ML-KEM-768`, `ML-DSA-65`, `AES-256`) relative to total cryptographic indicators.
- **`self-production` (100% / Grade A)**: Scans production application code (`src/main/`) while explicitly excluding `attack-lab`, `classical`, and test suites. It shows 0 critical findings and registers 100% quantum readiness due to PQC algorithm bindings in UI and configurations.
- **`self-tests` (73.2% / Grade F)**: Scans the entire project including test fixtures, intentional test vulnerabilities, and `crypto-scanner`'s own `rules.yaml`. By design, rules defining weak algorithms (MD5, DES, RC4) are flagged by the scanner itself, resulting in 61 findings and grade F.

---

## 3. Attack Definitions & Benchmark Constraints

### A. Meaning of "Tampering Succeeded" in CLASSICAL-VULNERABLE
- In the 15-cell matrix, Tampering for `CLASSICAL-VULNERABLE` is marked as **SUCCEEDED** not because the attacker successfully forged authenticated plaintext, but because flipping a bit caused a raw `AEADBadTagException` with **zero security telemetry logged**.
- In production environments, unhandled decryption exceptions create error-oracle side channels that allow attackers to infer padding or plaintext characteristics. In `CLASSICAL-HARDENED` and `HYBRID`, `TamperGuard` intercepts the exception, logs a forensic `TAMPER` event, and returns a uniform, non-oracle error.

### B. Benchmark Execution Context
- **Indicative Quick Mode**: Benchmarks run by default in `quick` mode (100 warmup, 500 iterations, 1 JMH fork), providing fast indicative timings rather than publication-grade multi-hour distributions.
- **CPU Measurement Caveat**: CPU time is sampled via `ThreadMXBean.getCurrentThreadCpuTime()`. On Windows, the thread scheduler resolution is typically 10–15 ms, introducing coarse-grained sampling noise compared to high-resolution Linux timers.

### C. Algorithm Maturity
- Post-quantum lattice-based algorithms (ML-KEM and ML-DSA) have undergone rigorous standardization (NIST PQC process 2016–2024), but have substantially less operational history than classical primitives like RSA and ECDH. This asymmetry is the primary rationale for deploying **Hybrid** mode during migration.

### D. Assurance Level
- The codebase is an academic and engineering proof-of-concept. It has not undergone formal mathematical verification (e.g., ProVerif / Tamarin) nor external third-party security auditing.

---

## 4. Future Work

1. **RFC 9370 / X25519MLKEM768 Real TLS 1.3 Groups**: Implement draft-ietf-tls-hybrid-design wire structures to enable interop with Google Chrome and Cloudflare test endpoints.
2. **JDK 24 Native JCE Integration**: Migrate from Bouncy Castle software wrappers to native JDK 24+ JEP 496 (`KEM` API) and JEP 497 (`Signature` API).
3. **Stateless Hash Signatures (SLH-DSA)**: Integrate NIST FIPS 205 (Sphincs+) for ultra-conservative long-term code signing and certificate authority backends.
4. **Fast Lattice Signatures (FN-DSA)**: Benchmark Falcon-512 signatures for bandwidth-constrained network links.
5. **Machine Learning Anomaly Detection**: Layer unsupervised network flow analysis alongside deterministic rule-based guards in `attack-engine`.
