# Capstone Viva Examination: 20 Likely Questions & Model Answers

Concise, authoritative answers (2–3 sentences each) designed for rapid recall during a viva examination.

---

### Q1: What does "ML" mean in ML-KEM and ML-DSA? Does it use Machine Learning?
**Answer**: No, "ML" stands for **Module-Lattice**, referring to algebraic module structures over polynomial rings ($R_q = \mathbb{Z}_q[X]/(X^n + 1)$) rather than artificial intelligence. These algorithms base their security on the worst-case hardness of the Module Learning with Errors (M-LWE) and Module Short Integer Solution (M-SIS) lattice problems.

---

### Q2: Why did you implement three distinct cipher suites (`CLASSICAL`, `HYBRID`, and `PQ_ONLY`)?
**Answer**: Three suites allow direct empirical comparison of migration trade-offs across security, wire size, and computational latency. `CLASSICAL` establishes the legacy baseline, `HYBRID` represents the recommended NIST transition standard preserving dual security, and `PQ_ONLY` measures the performance ceiling when classical overhead is completely eliminated.

---

### Q3: Is `HYBRID` actually quantum-safe if both halves aren't tested against a real quantum computer?
**Answer**: Yes, because the classical and post-quantum secrets are mathematically combined via HKDF ($\text{IKM} = ss_1 \parallel ss_2$), meaning an attacker must break *both* mathematical assumptions to recover the session key. Even if Shor's algorithm on a future quantum computer instantly solves the elliptic curve discrete logarithm for $ss_1$, $ss_2$ remains secure under the lattice hardness of ML-KEM-768.

---

### Q4: Is the MITM in the interactive Chat Demo real?
**Answer**: The Chat Demo simulates the outcome of a MITM breach in the browser UI by sharing keys with the attacker panel in vulnerable mode. However, a genuine two-leg TCP proxy is fully implemented in `attack-lab` (`MitmAttackTest`), where an active proxy terminates real socket connections to both endpoints, intercepts traffic, and decrypts payloads.

---

### Q5: Why is `PQ_ONLY` handshake latency faster than `CLASSICAL` in your benchmarks?
**Answer**: Because classical RSA-2048 private key signing requires expensive modular exponentiation, taking $\approx 869\ \mu\text{s}$ in our tests. In contrast, post-quantum ML-DSA-65 signing involves fast polynomial matrix-vector operations, executing in $\approx 704\ \mu\text{s}$, while ML-KEM encapsulation takes only $\approx 284\ \mu\text{s}$.

---

### Q6: What does "100% PQC-Ready" mean in the scanner report?
**Answer**: It is a static heuristic metric indicating that 100% of the cryptographic algorithm references detected in that target correspond to approved modern/post-quantum standards (such as ML-KEM, ML-DSA, or AES-256) with zero legacy findings. In `self-production`, all production configurations and UI bindings utilize approved primitives.

---

### Q7: How does your key schedule combiner guarantee independence between the two secrets?
**Answer**: `HybridKeySchedule` concatenates the classical and post-quantum secrets into the HKDF-Extract input ($\text{PRK} = \text{HMAC-SHA256}(\text{Salt}, ss_1 \parallel ss_2)$). Due to the strict avalanche effect of SHA-256, changing a single bit in either $ss_1$ or $ss_2$ results in completely uncorrelated pseudorandom keys, which we verify empirically in `HybridKeyScheduleTest`.

---

### Q8: Why is the total wire overhead 7.85x while key material overhead is 12.17x?
**Answer**: The 12.17x ratio ($6,098\ \text{B}$ vs $501\ \text{B}$) measures only raw cryptographic keys, ciphertexts, and signatures. When messages are framed inside Java socket streams with headers, nonces, and suite identifiers ($6,433\ \text{B}$ vs $820\ \text{B}$), the constant framing overhead dilutes the relative expansion down to 7.85x.

---

### Q9: What is the difference between Shor's algorithm and Grover's algorithm in their threat to this system?
**Answer**: Shor's algorithm solves discrete logarithms and integer factorization in polynomial time, completely destroying classical public-key cryptography (RSA and X25519). Grover's algorithm provides only a quadratic speedup against symmetric ciphers, effectively halving key strength; we mitigate this by using AES-256, which retains a quantum-safe 128-bit security margin.

---

### Q10: Why is AES-GCM nonce reuse considered catastrophic (VULN-3)?
**Answer**: In AES-GCM, reusing a 96-bit nonce under the same key generates an identical keystream, revealing the XOR of the plaintexts ($C_1 \oplus C_2 = P_1 \oplus P_2$). Furthermore, it allows an adversary to linearly solve for the internal GHASH authentication key ($H$), enabling arbitrary ciphertext forgery.

---

### Q11: How does `DowngradeGuard` prevent cipher suite stripping without extra network round trips?
**Answer**: The server's ML-DSA-65 digital signature is computed over the SHA-256 hash of the complete handshake transcript, which explicitly includes the client's offered suite list. If an on-path attacker strips `HYBRID` from `ClientHello`, the transcript hash computed by the client will not match the server's signature, causing the client to abort immediately.

---

### Q12: Why did you use Bouncy Castle instead of native Java standard library providers?
**Answer**: The project is built on JDK 21 LTS, which does not contain native implementations of NIST FIPS 203 or FIPS 204. Bouncy Castle 1.80 provides certified software implementations of ML-KEM and ML-DSA; native JDK support is scheduled for JDK 24+ via JEP 496 and JEP 497.

---

### Q13: In the 15-cell matrix, why is Tampering in `CLASSICAL-VULNERABLE` marked as "succeeded" if GCM threw an exception?
**Answer**: Because the modified ciphertext triggered an unhandled, raw JDK `AEADBadTagException` with **zero security telemetry logged**. In production, unhandled decryption exceptions create error-oracle side channels that leak information; in contrast, `TamperGuard` catches the error, logs a forensic `TAMPER` event, and returns a uniform sanitized error.

---

### Q14: What is the purpose of mutual `Finished` messages in the hybrid handshake?
**Answer**: Mutual `Finished` messages provide key confirmation by exchanging an HMAC-SHA256 tag over the full transcript using `finishedKey` derived from the session secrets. This proves to both parties that their peer computed identical keys and that no message in the handshake transcript was altered.

---

### Q15: Why does `self-tests` get a Grade F in the scanner while `self-production` gets a Grade A?
**Answer**: `self-tests` scans test fixtures, attack test cases, and the scanner's own `rules.yaml` file, which intentionally contains strings like `MD5`, `DES`, and `RC4` to define detection rules. In contrast, `self-production` scans only production application code, correctly registering 0 vulnerabilities and Grade A.

---

### Q16: How does `TimingGuard` mitigate side-channel timing leaks?
**Answer**: Standard array equality (`Arrays.equals` or `String.equals`) short-circuits on the first non-matching byte, leaking information about how many leading bytes were correct. `TimingGuard` enforces constant-time comparisons using `MessageDigest.isEqual`, executing in time proportional to array length regardless of content.

---

### Q17: Why retain classical X25519 in the hybrid suite if quantum computers will break it?
**Answer**: New post-quantum lattice algorithms have undergone years of NIST standardization but have less operational history than ECC. Retaining X25519 ensures that even if a catastrophic mathematical shortcut is discovered against ML-KEM, the system remains fully protected against classical adversaries.

---

### Q18: What is the purpose of Additional Authenticated Data (AAD) in our record protocol?
**Answer**: In our channel, AAD binds the 64-bit record sequence number and channel identifier into the GCM GHASH authentication tag without encrypting it. This ensures that an adversary cannot alter the sequence number or swap records between client and server directions without invalidating the tag.

---

### Q19: How does `ReplayGuard` handle out-of-order network packets while still blocking replays?
**Answer**: `ReplayGuard` implements a 64-bit sliding-window bitmask alongside strict sequence tracking. If a packet arrives out of order within the window, the guard verifies that its specific bit has not been previously set, accepts the packet, and marks the bit; duplicate sequence numbers are immediately rejected.

---

### Q20: What are the primary operational risks when an enterprise migrates to post-quantum hybrid TLS?
**Answer**: The primary risks are network packet fragmentation due to larger public keys and signatures (exceeding standard 1,500-byte MTUs), legacy middlebox interference (middleboxes dropping unfamiliar TLS extensions or large packets), and increased memory pressure on high-concurrency servers holding larger handshake buffers.
