# PQC-APS Presentation Structure (15 Slides)

Designed for a 5-minute capstone viva presentation (20 seconds per slide).

---

### Slide 1: Title & Executive Overview
- **Title**: PQC-APS: Post-Quantum Cryptographic Migration, Prevention & Evaluation
- **Bullet Points**:
  - Addresses the "Harvest Now, Decrypt Later" (HNDL) threat from quantum computing.
  - Implements NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) in a dual-engine hybrid architecture.
  - Evaluates security across 15 attack scenarios, static code scanning, and microbenchmarks.
- **Visual**: System Architecture Diagram (`docs/diagrams/architecture.md`)
- **Speaker Note (20s)**: "Good morning. PQC-APS addresses the urgent cryptographic migration needed before quantum computers break RSA and ECC. We built an end-to-end framework combining post-quantum key exchange, an offensive attack lab, a real-time defense engine, and static code scanning."

---

### Slide 2: The Quantum Threat (HNDL)
- **Title**: Why We Must Act Now: Harvest Now, Decrypt Later
- **Bullet Points**:
  - Shor's algorithm completely breaks discrete logs (ECDH) and integer factorization (RSA).
  - Adversaries are actively capturing and archiving encrypted government and enterprise traffic today.
  - Once a Cryptanalytically Relevant Quantum Computer emerges, stored classical sessions are instantly decrypted.
- **Visual**: Threat Model Timeline / HNDL Diagram
- **Speaker Note (20s)**: "Even though quantum computers capable of running Shor's algorithm are years away, data captured on the wire today will be decrypted retroactively. Post-quantum forward secrecy is required now to protect long-lived confidential data."

---

### Slide 3: Static Scanner: The Discovery Story
- **Title**: Discovery: Auditing Codebases for Quantum Vulnerabilities
- **Bullet Points**:
  - **`vulnerable-app` (Grade F)**: 16 legacy findings (RC4, MD5, static IVs, RSA-1024), 0% quantum-ready.
  - **`migrated-app` (Grade A)**: Remediated to AES-256-GCM and ML-KEM-768; 0 critical flaws, 100% quantum-ready.
  - **`self-production` (Grade A)**: The PQC-APS production codebase achieves 0 critical flaws and 100% readiness.
- **Visual**: Scanner Target Comparison Table (`docs/RESULTS.md` Table 6 or `screenshot-scanner.png`)
- **Speaker Note (20s)**: "Migration begins with discovery. Our static scanner evaluated a legacy baseline, giving it an F with 16 vulnerabilities. Refactoring to modern primitives in migrated-app yields an A and 100% quantum readiness, a standard our own production codebase matches."

---

### Slide 4: System Architecture & 11-Module Design
- **Title**: Architecture: Clean Decoupling Across 11 Modules
- **Bullet Points**:
  - Separation of concerns: cryptographic primitives, secure channel, attack engine, scanner, and UI.
  - Agility layer allows hot-swapping classical, hybrid, and pure post-quantum algorithms.
  - Centralized append-only `EventLog` and JSON telemetry feed all real-time dashboards.
- **Visual**: `docs/diagrams/architecture.md`
- **Speaker Note (20s)**: "The architecture is split into 11 Maven reactor modules. Primitives in `hybrid-kex` and `pq-auth` feed into `secure-channel`, while `attack-engine` independently guards socket streams, reporting forensic telemetry to the dashboard."

---

### Slide 5: The Post-Quantum Hybrid Handshake
- **Title**: The 8-Step Hybrid Handshake Protocol
- **Bullet Points**:
  - Combines classical Curve25519 ECDH with NIST FIPS 203 ML-KEM-768.
  - Authenticated by NIST FIPS 204 ML-DSA-65 digital signatures over the full transcript.
  - Mutual key confirmation via dual-direction HMAC-SHA256 Finished messages.
- **Visual**: `docs/diagrams/handshake-hybrid.md`
- **Speaker Note (20s)**: "Here is our 8-step hybrid handshake. Alice sends ephemeral X25519 and ML-KEM public keys. Bob encapsulates a quantum secret, computes classical Diffie-Hellman, signs the transcript, and both exchange Finished messages before opening AES-256-GCM."

---

### Slide 6: Dual-PRK Key Schedule Combiner
- **Title**: Key Schedule: The Hybrid Security Guarantee
- **Bullet Points**:
  - HKDF Extract combines secrets: $\text{IKM} = ss_1 \parallel ss_2$ with salt $= nonce_c \parallel nonce_s$.
  - Security holds if *either* X25519 *or* ML-KEM-768 remains unbroken.
  - Proven avalanche effect: flipping a single bit in either secret yields uncorrelated session keys.
- **Visual**: `docs/diagrams/key-schedule.md`
- **Speaker Note (20s)**: "Our key schedule concatenates both shared secrets into HKDF. Even if ML-KEM encounters a future mathematical breakthrough, X25519 protects classical security; if Shor's algorithm breaks X25519, ML-KEM keeps the session key completely secure."

---

### Slide 7: Classical Baseline & 4 Intentional Flaws
- **Title**: The Vulnerable Baseline: Protocol Flaws VULN-1 to VULN-4
- **Bullet Points**:
  - **VULN-1 (Downgrade)**: Signature omits offered suites list; attacker strips HYBRID undetected.
  - **VULN-2 (Replay)**: Receiver ignores sequence numbers; re-injected records accepted.
  - **VULN-3 (Nonce Reuse)**: Nonce counter resets to 0; keystream reuse leaks plaintexts.
  - **VULN-4 (MITM)**: Client skips public key pinning; rogue server intercepts channel.
- **Visual**: `docs/diagrams/handshake-classical.md`
- **Speaker Note (20s)**: "To demonstrate defense in depth, we built a vulnerable classical baseline with four critical architectural flaws: unauthenticated suite negotiation, disabled sequence checking, static nonces, and unpinned server keys."

---

### Slide 8: The Offensive Attack Lab
- **Title**: Attack Lab: Real Cryptographic Exploitation
- **Bullet Points**:
  - Real TCP network execution—no simulated mock results in `attack-lab`.
  - True two-leg MITM proxy binds intermediate sockets and decrypts intercepted traffic.
  - Automated test harness verifies vulnerability exploitation in classical mode.
- **Visual**: Attack Lab Test Output (`screenshot-attack-matrix.png` or `docs/diagrams/attack-flows.md`)
- **Speaker Note (20s)**: "Our attack lab is a live exploit harness. The MITM test actually spins up an on-path proxy, intercepts socket streams, terminates two handshake legs, and decrypts payloads. Replay tests inject captured byte arrays across the wire."

---

### Slide 9: The Prevention Engine: 8 Real-Time Guards
- **Title**: Defense Engine: 8 Forensic Defensive Guards
- **Bullet Points**:
  - Active guards: `DowngradeGuard`, `MitmGuard`, `ReplayGuard`, `NonceManager`, `TamperGuard`.
  - Implementation guards: `KeyReuseGuard`, `RandomnessGuard`, and `TimingGuard`.
  - Immediate fail-closed enforcement and structured JSONL forensic event logging.
- **Visual**: Defensive Guard Matrix (`docs/THREAT_MODEL.md` §4)
- **Speaker Note (20s)**: "The prevention engine deploys eight specialized guards. ReplayGuard checks monotonic sequence numbers, NonceManager prevents IV reuse, and TamperGuard catches ciphertext manipulation while preventing oracle leaks."

---

### Slide 10: 15-Cell Security Evaluation Matrix
- **Title**: Experimental Validation: The 15-Cell Security Matrix
- **Bullet Points**:
  - 5 attacks $\times$ 3 modes evaluated under full network execution.
  - `CLASSICAL-VULNERABLE`: All 5 attacks succeed completely.
  - `CLASSICAL-HARDENED` & `HYBRID`: 100% of attacks blocked with forensic events logged.
- **Visual**: 15-Cell Matrix Overview (`docs/RESULTS.md` Table 2)
- **Speaker Note (20s)**: "This matrix summarizes our empirical security results. Under vulnerable classical mode, all five attacks succeed. When guards are enabled in hardened classical and hybrid modes, every single attack is intercepted and blocked."

---

### Slide 11: Transmission Overhead: Wire & Key Sizes
- **Title**: Wire Size Analysis: Prototype Overhead
- **Bullet Points**:
  - Total handshake wire: **6,433 B** (Hybrid) vs **820 B** (Classical) $\to$ **7.85x ratio**.
  - Unframed key material: **6,098 B** vs **501 B** $\to$ **12.17x ratio**.
  - Driven by post-quantum keys: ML-KEM-768 public key (1,184 B) and ML-DSA-65 signature (3,309 B).
- **Visual**: Wire Size Comparison Table (`docs/RESULTS.md` Table 3 or `screenshot-handshake.png`)
- **Speaker Note (20s)**: "Post-quantum security comes with wire overhead. Our hybrid handshake requires 6,433 bytes compared to 820 bytes for classical—a 7.85x wire increase driven by ML-KEM's 1,184-byte public key and ML-DSA's 3.3-kilobyte signature."

---

### Slide 12: Computational Performance & Throughput
- **Title**: Computational Performance & AES-GCM Throughput
- **Bullet Points**:
  - Hybrid handshake CPU overhead: **+312.5 µs (1.22x)** vs classical baseline.
  - Post-quantum operations are fast: ML-KEM keygen is 277 µs; ML-DSA signing is 704 µs.
  - AES-256-GCM symmetric transport sustains **> 2,200 MB/s** for 64 KB records.
- **Visual**: Latency & Throughput Table (`docs/RESULTS.md` Table 5)
- **Speaker Note (20s)**: "Computationally, hybrid cryptography is surprisingly efficient. Handshake CPU time increased by only 312 microseconds—a 1.22x factor. Once the handshake finishes, AES-256-GCM sustains over 2.2 gigabytes per second on large records."

---

### Slide 13: Interactive Dashboard & Chat Demonstration
- **Title**: Interactive Visualization & Chat Demonstration
- **Bullet Points**:
  - Live Spring Boot / Chart.js dashboard displaying real-time telemetry and benchmark graphs.
  - Handshake visualizer step-by-step breakdown separating crypto computation from display delay.
  - Interactive chat panel showing real-time plaintext interception in vulnerable mode vs guard alerts.
- **Visual**: `screenshot-chat-demo.png` or `screenshot-overview.png`
- **Speaker Note (20s)**: "We built a web dashboard for live demonstrations. The handshake visualizer steps through message framing, while the chat demo visually illustrates how an active MITM eavesdrops in vulnerable mode versus being blocked in hybrid mode."

---

### Slide 14: Engineering Limitations & Honest Trade-Offs
- **Title**: Limitations & Real-World Considerations
- **Bullet Points**:
  - Framing uses Java object serialization, not RFC 8446 byte-exact TLS 1.3 records.
  - Tested on JDK 21 via Bouncy Castle; native JCE provider integration requires JDK 24+.
  - Matrix shows active attack blocking; the quantum harvest threat is measured via key schedule independence.
- **Visual**: Limitations Summary (`docs/LIMITATIONS.md`)
- **Speaker Note (20s)**: "We emphasize scientific honesty: our framing uses Java socket serialization rather than RFC 8446 wire bytes. Furthermore, while the attack matrix proves active defense, quantum resistance itself is proven by key combiner independence."

---

### Slide 15: Conclusion & Future Work
- **Title**: Conclusion & Capstone Contributions
- **Bullet Points**:
  - Built and verified a complete, dual-engine post-quantum migration framework with 192 passing tests.
  - Quantified real overheads (7.85x wire size, 1.22x CPU impact) on modern hardware.
  - Future Work: RFC 9370 real TLS 1.3 groups, native JDK 24 JCE providers, and SLH-DSA.
- **Visual**: Test Summary Tile (192/192 Tests Passing across 10 modules)
- **Speaker Note (20s)**: "In conclusion, PQC-APS demonstrates that post-quantum hybrid migration is practical today with modest CPU overhead. All 192 tests pass across 10 reactor modules. Thank you, and I look forward to your questions."
