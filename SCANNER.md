# PQC-APS :: Crypto Inventory Scanner (SCANNER.md)

## 1. Overview
The **Crypto Inventory Scanner** (`crypto-scanner`) is an automated static and runtime audit engine designed to catalog cryptographic assets, evaluate quantum vulnerability exposure, and assess cryptographic hygiene across source trees, configuration files, and live TLS endpoints.

It identifies classical public-key algorithms vulnerable to Shor's algorithm (RSA, ECC, Diffie-Hellman), deprecated/broken symmetric ciphers and digests (DES, 3DES, RC4, Blowfish, MD5, SHA-1), hardcoded credentials, insecure pseudo-random generators, static IV allocations, and legacy TLS endpoints. Simultaneously, it tracks positive adoption of NIST Post-Quantum Cryptography standards (ML-KEM-768, ML-DSA-65).

---

## 2. Risk Scoring Formula

### 2.1 Per-Finding Risk Score ($0 \le S \le 100$)
Each finding is assigned a base score determined by its risk category:

| Category | Description | Base Score |
| :--- | :--- | :---: |
| `CIPHER_BROKEN` / `CIPHER_WEAK` | Factored RSA (<2048), DES, 3DES, RC4, Blowfish, AES-ECB, Static IV | **95** |
| `SECRET_HARDCODED` | PEM private keys, hardcoded keys/passwords/tokens | **90** |
| `KEY_EXCHANGE_QV` | RSA, X25519, ECDH, DH (Harvest-Now-Decrypt-Later risk) | **85** |
| `RNG_WEAK` | `java.util.Random` or `Math.random()` near secrets/nonces | **80** |
| `TLS_LEGACY` | SSLv3, TLS 1.0, TLS 1.1, Expired certificates | **80** |
| `HASH_BROKEN` | MD5, SHA-1 collision-vulnerable digests | **70** |
| `SIGNATURE_QV` | RSA, ECDSA, Ed25519 signatures (Shor forgery risk) | **60** |
| `SYMMETRIC_INFO` | AES-128 (Grover quantum search reduces to 64-bit margin) | **20** |
| `PQC_READY` | ML-KEM-768, ML-DSA-65, SLH-DSA, FN-DSA | **0** |

#### Data Lifetime Multiplier
For sensitive data requiring long retention windows, retroactive quantum decryption (Harvest-Now-Decrypt-Later) represents an immediate threat. If configured with `dataLifetimeYears > 10`:
$$\text{Score}_{\text{adjusted}} = \min(100, \, \text{round}(\text{BaseScore} \times 1.2)) \quad \text{for } \text{KEY\_EXCHANGE\_QV and ENCRYPTION\_QV}$$
For example, base 85 key exchanges scale to $\min(100, 85 \times 1.2) = 100$.

### 2.2 Finding Severity Classification
Findings map from their calculated score to standard severity levels:
- **CRITICAL**: Score $\ge 90$
- **HIGH**: $70 \le \text{Score} < 90$
- **MEDIUM**: $40 \le \text{Score} < 70$
- **LOW**: $10 \le \text{Score} < 40$
- **INFO**: $\text{Score} < 10$ (also reserved for `PQC_READY` and `SYMMETRIC_INFO`)

### 2.3 Project-Level Overall Risk Score & Grade
The overall project risk score weighs the most severe risk heavily while accounting for average technical debt:
$$\text{OverallScore} = \text{round}(0.6 \times \max(S) + 0.4 \times \text{avg}(S))$$
*(Evaluated over all non-PQC findings; $0$ if clean).*

#### Letter Grade Scale
- **Grade A**: Score $0 - 20$ (Excellent; quantum-safe or low informational findings)
- **Grade B**: Score $21 - 40$ (Good; minor classical legacy items)
- **Grade C**: Score $41 - 60$ (Moderate; legacy signatures or moderate technical debt)
- **Grade D**: Score $61 - 80$ (Poor; broken hashes, legacy TLS, or unmitigated quantum key exchange)
- **Grade F**: Score $81 - 100$ (Critical; broken ciphers, weak keys, hardcoded secrets)

### 2.4 Quantum Readiness Percentage
Measures the proportion of public-key cryptography that has migrated to post-quantum standards:
$$\text{QuantumReadiness} = \frac{\text{Count}(\text{PQC-READY})}{\text{Count}(\text{PQC-READY}) + \text{Count}(\text{Quantum-Vulnerable Public-Key Uses})} \times 100\%$$

---

## 3. Secret Redaction Policy
To avoid propagating credentials or sensitive data into vulnerability logs and reports, the scanner applies strict masking:
- Retains only the first 4 characters of any discovered credential or private key header.
- Replaces all subsequent characters with `****`.
- Example: `"DUMMY_SECRET_KEY_1234567890"` $\rightarrow$ `"DUMM****"`.
- Tested in `SecretRedactionTest.java` to guarantee zero raw secret leakage in `scan-report.json`.

---

## 4. Detection Mechanics

### 4.1 Java JCA Literal & Key Size Extraction
Scans `.java` source files using regex string literal matching on standard JCA factories:
```text
(Cipher|KeyPairGenerator|KeyAgreement|Signature|MessageDigest|Mac|KeyGenerator|KeyFactory|SecureRandom).getInstance("...")
```
Nearby `.initialize(n)` and `.init(n)` calls within a $\pm 4$ line window are inspected to distinguish between critically weak RSA (<2048) and standard classical RSA ($\ge 2048$), and between AES-128 and AES-256.

### 4.2 Insecure Randomness and Static Nonces
- Flags `new java.util.Random()` or `Math.random()` when instantiated near security keywords (`key`, `nonce`, `iv`, `token`, `secret`, `salt`).
- Flags static IV patterns such as `new GCMParameterSpec(128, new byte[12])` or unrandomized byte allocations passed directly as nonces.

### 4.3 Multi-Language & Config File Support
Scans `.py`, `.js`, `.ts`, `.properties`, `.yml`, `.yaml`, `.xml`, `.conf`, and `.pem` files, recognizing hash calls (`hashlib.md5`), cipher specs (`DES`, `RC4`, `AES-128`), PEM blocks, and hardcoded secrets.
Excludes `target/`, `.git/`, `node_modules/`, `.m2/`, binary files (detected by null bytes), and files exceeding 1 MB.

### 4.4 TLS Endpoint Probing & JDK 21 Limitation
Probes endpoints using an `SSLSocket` handshake with a permissive trust manager.
- Extracts TLS protocol version, cipher suite, certificate validity dates, subject public key algorithm, and signature algorithm.
- **Safety Guard**: Scans are restricted to `localhost` and `127.0.0.1`. Remote hosts require the explicit authorization flag `--i-own-this-target`.
- **Known Limitation**: JDK 21 does not yet support Post-Quantum Key Encapsulation Groups (e.g. `X25519MLKEM768`) in `sun.security.ssl.NamedGroup`. The scanner accurately audits certificates and negotiated TLS suites but documents "PQ key exchange: not detectable with this JDK".

---

## 5. CLI Usage & CI/CD Integration

### Commands
```powershell
# Scan source code and config directory
java -jar crypto-scanner.jar scan --path <dir> [--out scan-report.json] [--lifetime <years>]

# Probe local TLS endpoint
java -jar crypto-scanner.jar scan --tls localhost:8443 [--out scan-report.json]

# Probe authorized external TLS endpoint
java -jar crypto-scanner.jar scan --tls internal.company.com:443 --i-own-this-target

# CI/CD enforcement: exit with code 2 if any CRITICAL or HIGH findings exist
java -jar crypto-scanner.jar scan --path . --fail-on HIGH
```

---

## 6. Demonstration Scan Results

### 6.1 Vulnerable Application (`samples/vulnerable-app`)
```text
========================================================================================================================
  PQC-APS CRYPTOGRAPHIC INVENTORY SCAN REPORT
  Target: Directory: samples/vulnerable-app | Findings: 16   | Grade: F  | Quantum Readiness: 0.0  % | Overall Score: 88/100
========================================================================================================================
Risk  | Severity  | Category         | Algorithm/Pattern    | Location                   | Recommendation          
------+-----------+------------------+----------------------+----------------------------+-------------------------
95    | CRITICAL  | CIPHER_BROKEN    | RC4/Blowfish         | legacy_service.py:19       | Replace immediately w...
95    | CRITICAL  | CIPHER_BROKEN    | RC4/Blowfish         | legacy_service.py:20       | Replace immediately w...
95    | CRITICAL  | CIPHER_BROKEN    | RSA-1024             | ...ulnerableCrypto.java:23 | Upgrade immediately t...
95    | CRITICAL  | CIPHER_BROKEN    | DES/CBC/PKCS5Padding | ...ulnerableCrypto.java:32 | Migrate to AES-256-GC...
95    | CRITICAL  | CIPHER_BROKEN    | AES/ECB/PKCS5Padding | ...ulnerableCrypto.java:35 | Use AES-GCM or AES-CB...
90    | CRITICAL  | SECRET_HARDCODED | HARDCODED_CREDENTIAL | app-config.yml:9           | Externalize secrets t...
90    | CRITICAL  | SECRET_HARDCODED | HARDCODED_CREDENTIAL | legacy_service.py:7        | Externalize secrets t...
90    | CRITICAL  | SECRET_HARDCODED | HARDCODED_CREDENTIAL | ...ulnerableCrypto.java:19 | Externalize secrets t...
90    | CRITICAL  | SECRET_HARDCODED | PEM_PRIVATE_KEY      | test-private.pem:1         | Externalize secrets t...
80    | HIGH      | RNG_WEAK         | java.util.Random ... | ...ulnerableCrypto.java:43 | Always use java.secur...
70    | HIGH      | HASH_BROKEN      | MD5                  | app-config.yml:7           | Replace with SHA-256,...
70    | HIGH      | HASH_BROKEN      | MD5                  | legacy_service.py:10       | Replace with SHA-256,...
70    | HIGH      | HASH_BROKEN      | MD5                  | legacy_service.py:11       | Replace with SHA-256,...
70    | HIGH      | HASH_BROKEN      | MD5                  | ...ulnerableCrypto.java:28 | Replace with SHA-256,...
20    | INFO      | SYMMETRIC_INFO   | AES-128              | app-config.yml:6           | Upgrade to AES-256 fo...
20    | INFO      | SYMMETRIC_INFO   | AES-128              | ...ulnerableCrypto.java:38 | Upgrade to AES-256 fo...
========================================================================================================================
  Counts: CRITICAL: 9 | HIGH: 5 | MEDIUM: 0 | LOW: 0 | INFO: 2 (PQC-READY: 0)
  OVERALL RISK GRADE: [F] (Risk Score: 88/100) | QUANTUM READINESS: 0.0%
========================================================================================================================
```

### 6.2 Migrated Application (`samples/migrated-app`)
```text
========================================================================================================================
  PQC-APS CRYPTOGRAPHIC INVENTORY SCAN REPORT
  Target: Directory: samples/migrated-app | Findings: 2    | Grade: A  | Quantum Readiness: 100.0% | Overall Score: 0/100
========================================================================================================================
Risk  | Severity  | Category         | Algorithm/Pattern    | Location                   | Recommendation          
------+-----------+------------------+----------------------+----------------------------+-------------------------
0     | INFO      | PQC_READY        | ML-KEM-768           | ...ed/ModernCrypto.java:21 | No migration needed. ...
0     | INFO      | PQC_READY        | ML-DSA-65            | ...ed/ModernCrypto.java:25 | No migration needed. ...
========================================================================================================================
  Counts: CRITICAL: 0 | HIGH: 0 | MEDIUM: 0 | LOW: 0 | INFO: 2 (PQC-READY: 2)
  OVERALL RISK GRADE: [A] (Risk Score: 0/100) | QUANTUM READINESS: 100.0%
========================================================================================================================
```

### 6.3 PQC-APS Repository Scan (`.`)
- Identifies Phase 1 legacy baseline primitives: RSA-2048 (`RsaSigner.java`), X25519 (`X25519KeyExchange.java`).
- Identifies Phase 3 Post-Quantum implementations: ML-KEM-768 (`hybrid-kex`), ML-DSA-65 (`pq-auth`).
- Total Findings: 81 (including attack demo test vectors).
- Quantum Readiness: **73.9%** across all public-key instances.
