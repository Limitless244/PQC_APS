# PQC-APS Demonstration & Submission Screenshot Checklist

This checklist specifies the exact views, interactions, and verification elements to capture for capstone presentation slides, final documentation, and video demonstration recordings.

---

## 1. Overview Page (`http://localhost:8080/`)

- [ ] **Capture**: `screenshot-01-overview.png`
- [ ] **URL**: `http://localhost:8080/#overview`
- [ ] **Pre-conditions**: Backend started with `powershell -File .\mvn.ps1 spring-boot:run` or standalone dashboard jar.
- [ ] **Required Elements Visible**:
  - **Total Reactor Tests Tile**: Displays `192/192` with caption `Across 10 modules` (loaded dynamically from `data/test-summary.json`).
  - **Throughput Tile**: Displays `> 2,200 MB/s` with one decimal place (`2,248.1 MB/s`), accompanied by host JDK (`JDK 21.0.10`) and CPU cores (`16 cores`).
  - **Security Matrix Badge**: `10/10 Defended in Hardened/Hybrid` (or summary status).
  - **PQC Production Readiness Tile**: `100% PQC Ready (Grade A)`.
  - **Quick-Navigation Cards**: Direct links to Handshake, Attack Lab, Scanner, Benchmarks, and Chat Demo.

---

## 2. Handshake Visualizer Page (`#handshake`)

### Screenshot 2A: Hybrid Mode Wire Breakdown & Crypto Time
- [ ] **Capture**: `screenshot-02a-handshake-hybrid.png`
- [ ] **Action**:
  1. Navigate to Handshake tab.
  2. Select cipher suite: `HYBRID (X25519 + ML-KEM-768 + ML-DSA-65)`.
  3. Click **"Run Handshake"**.
- [ ] **Required Elements Visible**:
  - **Primary Total Wire Size**: `6,433 Bytes` prominently displayed.
  - **Message Breakdown**:
    - `ClientHello`: `1,504 B` wire (1,356 B payload).
    - `ServerHello`: `4,675 B` wire (4,488 B payload).
    - `Client Finished`: `127 B` wire.
    - `Server Finished`: `127 B` wire.
  - **Unframed Payload Label**: `6,098 B (payload before framing)`.
  - **Measured Crypto Time**: Primary nanoTime metric in milliseconds (e.g. `~1.8 ms`), cleanly isolated from animation/display delay.
  - **First Run Badge**: Marked `Cold Start (JIT compilation included)` on run 1.

### Screenshot 2B: Multi-Run Benchmark ("Run x5")
- [ ] **Capture**: `screenshot-02b-handshake-run5.png`
- [ ] **Action**:
  1. Click **"Run x5"** button.
- [ ] **Required Elements Visible**:
  - Progress indicator completing 5 consecutive handshakes.
  - Summary card reporting **Mean** and **Min** elapsed crypto time across the last 4 warmed runs (excluding cold start).

### Screenshot 2C: Classical Baseline Comparison
- [ ] **Capture**: `screenshot-02c-handshake-classical.png`
- [ ] **Action**:
  1. Select cipher suite: `CLASSICAL (X25519 + RSA-2048)`.
  2. Click **"Run Handshake"**.
- [ ] **Required Elements Visible**:
  - Primary total wire size: `820 Bytes` (111 B ClientHello, 390 B ServerHello, 0 B Finished).
  - Unframed payload: `501 Bytes`.
  - Visual comparison badge showing `~7.85x` wire expansion for Hybrid.

---

## 3. Attack Matrix & Exploitation Page (`#attacks`)

### Screenshot 3A: Complete 15-Cell Grid
- [ ] **Capture**: `screenshot-03a-attack-matrix.png`
- [ ] **URL**: `http://localhost:8080/#attacks`
- [ ] **Required Elements Visible**:
  - 5 Attack Rows: `Downgrade`, `MITM`, `Replay`, `Nonce Reuse`, `Tampering`.
  - 3 Mode Columns: `CLASSICAL-VULNERABLE`, `CLASSICAL-HARDENED`, `HYBRID`.
  - `CLASSICAL-VULNERABLE` column: All 5 cells show red badge `❌ SUCCEEDED (Vulnerable)`.
  - `CLASSICAL-HARDENED` column: All 5 cells show green badge `✔ BLOCKED (Defended)`.
  - `HYBRID` column: All 5 cells show green badge `✔ BLOCKED (Defended)`.

### Screenshot 3B: Evidence & Telemetry Modal
- [ ] **Capture**: `screenshot-03b-attack-modal.png`
- [ ] **Action**:
  1. Click on the `Downgrade` cell under `HYBRID` (or `MITM` under `CLASSICAL-VULNERABLE`).
- [ ] **Required Elements Visible**:
  - Modal popup titled **Attack Diagnostic Evidence**.
  - Event ID: e.g. `9f4a96bb-053c-4cc6-8bb1-94dc66848112`.
  - Diagnostic detail sentence: `ClientHello suites stripped -> ML-DSA-65 signed transcript mismatch, downgrade blocked`.
  - Defensive action badge: `BLOCKED` via `DowngradeGuard`.

---

## 4. Static Crypto Scanner Page (`#scanner`)

### Screenshot 4A: Target Comparison Table
- [ ] **Capture**: `screenshot-04a-scanner-comparison.png`
- [ ] **URL**: `http://localhost:8080/#scanner`
- [ ] **Pre-conditions**: Page loaded (table populates automatically from `data/scan-report-*.json` on load without clicking Scan).
- [ ] **Required Elements Visible**:
  - Table with 5 targets:
    1. `vulnerable-app`: 16 findings, 9 Critical, 5 High, Score `99`, Grade **F**, Quantum Readiness **0.0%**.
    2. `migrated-app`: 2 findings, 0 Critical, 0 High, Score `0`, Grade **A**, Quantum Readiness **100.0%**.
    3. `self`: 20 findings, 3 Critical, 4 High, Score `85`, Grade **F**, Quantum Readiness **76.5%**.
    4. `self-production`: 13 findings, 0 Critical, 0 High, Score `0`, Grade **A**, Quantum Readiness **100.0%**.
    5. `self-tests`: 61 findings, 15 Critical, 14 High, Score `100`, Grade **F**, Quantum Readiness **73.2%**.

### Screenshot 4B: Vulnerable Findings Deep-Dive
- [ ] **Capture**: `screenshot-04b-scanner-findings.png`
- [ ] **Action**:
  1. Select target `vulnerable-app` in the scan selector.
  2. View findings list below.
- [ ] **Required Elements Visible**:
  - Critical rule cards: `RULE-RC4-BLOWFISH`, `RULE-MD5`, `RULE-STATIC-IV`, `RULE-RSA-WEAK`.
  - Redacted 4-character code snippets (e.g. `ciph...`, `hash...`).
  - Recommended migration target (e.g. `AES-256-GCM / ML-KEM-768`).

---

## 5. Benchmarks Page (`#benchmarks`)

- [ ] **Capture**: `screenshot-05-benchmarks.png`
- [ ] **URL**: `http://localhost:8080/#benchmarks`
- [ ] **Required Elements Visible**:
  - Benchmark execution mode badge: `quick mode (indicative)` or `full mode (mean ± SD)`.
  - Primitive latency charts (Chart.js bar charts for Keygen, Encapsulate, Sign, Verify).
  - CPU time comparison card: Classical (`1,406.2 µs`), Hybrid (`1,718.8 µs`), PQ-Only (`937.5 µs`), Overhead (`+312.5 µs`).
  - AES-256-GCM throughput chart showing 1 KB vs 64 KB records.

---

## 6. Live Chat Demonstration Page (`#chat`)

### Screenshot 6A: Classical-Vulnerable Plaintext Interception
- [ ] **Capture**: `screenshot-06a-chat-mitm.png`
- [ ] **Action**:
  1. Select mode: `CLASSICAL-VULNERABLE`.
  2. Click **"Reset Session"**.
  3. Type message in Alice's box: `Transfer authorization $5,000 to Account #8491` and click **"Send"**.
- [ ] **Required Elements Visible**:
  - Alice's message bubble: `Transfer authorization $5,000...`.
  - Eve's (Attacker) log: **Actual decrypted plaintext**:
    `[MITM Intercepted Plaintext]: "Transfer authorization $5,000 to Account #8491"`.
  - Bob's receiver bubble: `ACCEPTED (seq=0 verified)`.

### Screenshot 6B: Hybrid Mode Ciphertext Privacy
- [ ] **Capture**: `screenshot-06b-chat-hybrid-privacy.png`
- [ ] **Action**:
  1. Select mode: `HYBRID`.
  2. Click **"Reset Session"**.
  3. Type message in Alice's box: `Quantum confidential payload` and click **"Send"**.
- [ ] **Required Elements Visible**:
  - Eve's log: Only encrypted ciphertext hex displayed (`[Encrypted Record seq=0]: 4a7c1b... (41 bytes ciphertext)`). Plaintext is unreadable.

### Screenshot 6C: Hybrid Mode Replay Attack Blocked
- [ ] **Capture**: `screenshot-06c-chat-replay-blocked.png`
- [ ] **Action**:
  1. In the open `HYBRID` session, click **"Attacker: Replay Last Message"**.
- [ ] **Required Elements Visible**:
  - Attacker Action Log: Displays red warning:
    `[REPLAY] BLOCKED: Replay of record seq=0 BLOCKED by ReplayGuard: Replay attack detected: sequence number 0 already processed`.
  - Bob's guard status badge: `🛡 BLOCKED (ReplayGuard active)`.
  - Real-time event counter increments on the dashboard.

### Screenshot 6D: Hybrid Mode Tampering (Bit Flip) Blocked
- [ ] **Capture**: `screenshot-06d-chat-tamper-blocked.png`
- [ ] **Action**:
  1. In the open `HYBRID` session, click **"Attacker: Flip Bit in Ciphertext"**.
- [ ] **Required Elements Visible**:
  - Attacker Action Log: Displays red warning:
    `[TAMPER] BLOCKED: Tampering BLOCKED by TamperGuard: Record decryption failed (authentication tag mismatch)`.
  - Bob's guard status badge: `🛡 BLOCKED (TamperGuard active)`.
