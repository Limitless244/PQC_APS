# Capstone Dissertation / Report Outline

**Title**: PQC-APS: A Dual-Engine Post-Quantum Cryptographic Migration, Attack Prevention, and Performance Evaluation Framework  
**Target Length**: 55–65 pages  

---

## Chapter Breakdown & Mapping

| Ch # | Chapter Title | Target Pages | Source Documents / Feed | Core Deliverables & Tables |
| :---: | :--- | :---: | :--- | :--- |
| **-** | **Abstract & Executive Summary** | 1–2 | `docs/RESULTS.md` | Problem statement, methodology, 192/192 test summary, key benchmark findings (7.85x wire overhead, 1.22x CPU). |
| **1** | **Introduction** | 3–4 | `docs/LIMITATIONS.md` | Problem context, Harvest-Now-Decrypt-Later (HNDL) paradigm, project objectives, contributions, report roadmap. |
| **2** | **Theoretical Background** | 5–6 | Literature | Quantum threat: Shor's algorithm (breaks RSA/ECC) vs Grover's algorithm (halves symmetric keys). Lattice cryptography, Module Learning with Errors (M-LWE), and Module Short Integer Solution (M-SIS). |
| **3** | **Standards & Literature Review** | 4–5 | NIST FIPS Standards | NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), IETF hybrid TLS drafts (RFC 9370, X25519MLKEM768). Migration guidelines (CNSA 2.0). |
| **4** | **Threat Modeling & Requirements** | 4–5 | `docs/THREAT_MODEL.md` | Assets, Dolev-Yao on-path attacker model, CRQC capabilities, trust assumptions, 8 guard threat matrix, explicit out-of-scope boundaries. |
| **5** | **System Architecture** | 4–5 | `docs/diagrams/architecture.md` | 11-module reactor architecture, decoupling of primitives, protocol channel, prevention engine, scanner, and presentation layer. Data flow via `data/`. |
| **6** | **Handshake & Key Schedule Design** | 6–8 | `docs/diagrams/handshake-hybrid.md`<br/>`docs/diagrams/key-schedule.md` | 8-step hybrid handshake protocol with mutual Finished confirmation. Dual-PRK HKDF combiner architecture: why $ss_1 \parallel ss_2$ guarantees unbroken forward secrecy. |
| **7** | **The Classical Vulnerability Baseline** | 4–5 | `docs/diagrams/handshake-classical.md` | Implementation of `CLASSICAL-VULNERABLE`: intentional flaws VULN-1 (downgrade), VULN-2 (replay), VULN-3 (nonce reuse), VULN-4 (missing key pinning). |
| **8** | **Offensive Attack Lab** | 5–6 | `attack-lab/` test fixtures<br/>`docs/RESULTS.md` §2 | Active exploitation harness: stripping suites, two-leg TCP MITM proxy, packet re-injection, GCM keystream recovery, ciphertext bit-flipping. |
| **9** | **Real-Time Prevention Engine** | 6–7 | `docs/diagrams/attack-flows.md`<br/>`attack-engine/` source | Deep dive into the 8 defensive guards (`DowngradeGuard`, `MitmGuard`, `ReplayGuard`, `NonceManager`, `TamperGuard`, etc.). Event telemetry schema in `EventLog`. |
| **10** | **Static Cryptographic Scanner** | 4–5 | `docs/RESULTS.md` §6<br/>`crypto-scanner/` source | AST/regex rule engine, YAML rule registry (`RULE-MD5`, `RULE-RC4`, `RULE-STATIC-IV`, `RULE-RSA-WEAK`), risk scoring formula, quantum readiness calculation. |
| **11** | **Evaluation & Benchmark Methodology** | 4–5 | `docs/RESULTS.md` §3–5 | Wire measurement method (`ObjectOutputStream` socket serialization), JMH harness for latency and AES-256-GCM throughput, CPU profiling via `ThreadMXBean`. |
| **12** | **Experimental Results & Analysis** | 6–8 | `docs/RESULTS.md` (all tables)<br/>`docs/SCREENSHOTS.md` | Detailed analysis: 15-cell matrix verification, 6,433 B vs 820 B wire size breakdown, 7.85x ratio analysis, CPU overhead (+312.5 µs), scanner validation across 5 targets. |
| **13** | **Engineering Limitations & Trade-Offs** | 3–4 | `docs/LIMITATIONS.md` | Honest analysis of simulation boundaries (Chat demo vs attack lab proxy), JDK 21 Bouncy Castle constraints, ThreadMXBean resolution, lack of formal proofs. |
| **14** | **Conclusion & Future Directions** | 2–3 | `docs/LIMITATIONS.md` §4 | Summary of achievements: production-ready hybrid prototype, 192 verified unit/system tests. Future work: RFC 9370 wire compatibility, JDK 24 native JCE. |
| **15** | **References & Appendix** | 4–5 | External literature | NIST FIPS publications, academic papers on lattice cryptanalysis, full rule registry dump, surefire execution logs. |

---

## Key Figures & Tables Placement

1. **Figure 5.1**: High-level 11-module architecture diagram (`docs/diagrams/architecture.md`).
2. **Figure 6.1**: Sequence diagram of the 8-step Hybrid handshake (`docs/diagrams/handshake-hybrid.md`).
3. **Figure 6.2**: HKDF dual-PRK key schedule combiner (`docs/diagrams/key-schedule.md`).
4. **Figure 7.1**: Classical baseline showing VULN-1 through VULN-4 (`docs/diagrams/handshake-classical.md`).
5. **Figure 9.1**: Guard interception diagrams across the 5 primary attacks (`docs/diagrams/attack-flows.md`).
6. **Table 12.1**: The 15-cell security evaluation matrix (`docs/RESULTS.md` Table 2).
7. **Table 12.2**: Wire sizes and transmission overhead per cipher suite (`docs/RESULTS.md` Table 3).
8. **Table 12.3**: Cryptographic primitive key and signature dimensions (`docs/RESULTS.md` Table 4).
9. **Table 12.4**: Latency, CPU time, and AES-256-GCM throughput (`docs/RESULTS.md` Table 5).
10. **Table 12.5**: Static scanner comparison across baseline, migrated, and self targets (`docs/RESULTS.md` Table 6).
