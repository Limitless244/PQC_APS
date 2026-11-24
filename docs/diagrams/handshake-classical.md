# Classical Baseline Handshake Protocol (`CLASSICAL-VULNERABLE` vs `CLASSICAL-HARDENED`)

Implemented in `com.pqcaps.classical.ClassicalHandshake` (`classical` module). Uses Curve25519 for key exchange, RSA-2048 PKCS#1 v1.5 for signatures, and AES-256-GCM for symmetric transport. Shows the four intentional Phase 1 architectural vulnerabilities (`VULN-1` through `VULN-4`) and their hardened mitigations.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Client (Alice)
    actor Eve as Attacker / MITM (Eve)
    actor Bob as Server (Bob)

    Note over Alice,Bob: Step 1: Ephemeral Key Generation
    Alice->>Alice: Generate ephemeral X25519 keypair (xsk_c, xpk_c)<br/>Generate 32-byte client nonce (nonce_c)

    Note over Alice,Bob: Step 2: ClientHello (111 Bytes)
    Alice->>Eve: ClientHello(xpk_c [32 B], offeredSuites=["HYBRID", "CLASSICAL"], nonce_c [32 B])
    critical [VULN-1: Downgrade Attack]
        Eve->>Bob: Stripped ClientHello(xpk_c, offeredSuites=["CLASSICAL"], nonce_c)
    option Hardened Defence
        Alice->>Bob: Unmodified ClientHello with offered suites
    end

    Note over Bob: Step 3: Key Derivation & Server Signing
    Bob->>Bob: Generate ephemeral X25519 keypair (xsk_s, xpk_s)<br/>Compute ss = X25519(xsk_s, xpk_c) [32 B]<br/>Derive keys: HKDF-SHA256(ss, nonce_c || nonce_s) -> c2s, s2c
    critical [VULN-1 (Server Transcript)]: Server Signature Omits Suites List
        Bob->>Bob: Vulnerable: signs transcript excluding offeredSuites {xpk_c, xpk_s, nonce_c, nonce_s}<br/>Hardened: signs full transcript including offeredSuites
    end
    Bob->>Bob: Generate signature = RSA-2048.sign(serverIdentityKey, transcript) [256 B]

    Note over Alice,Bob: Step 4: ServerHello (390 Bytes)
    Bob->>Eve: ServerHello(xpk_s [32 B], suite="CLASSICAL", nonce_s [32 B], signature [256 B])
    critical [VULN-4: MITM Rogue Key Injection]
        Eve->>Alice: Rogue ServerHello with Eve's X25519 key and rogue RSA signature
    option Hardened Defence
        Bob->>Alice: Authentic ServerHello from Bob
    end

    Note over Alice: Step 5: Verification & Key Derivation
    critical [VULN-4 (Client Verification)]: Skipping Server Key Pinning
        Alice->>Alice: Vulnerable: skips server key pinning check (accepts Eve's rogue key)<br/>Hardened: verifies RSA signature against pinnedServerKey (rejects Eve's key)
    end
    critical [VULN-1 (Client Downgrade Check)]: Suite List Integrity Check
        Alice->>Alice: Vulnerable: cannot detect suite downgrade because Bob omitted suites from signature<br/>Hardened: signature verification fails due to transcript hash mismatch
    end
    Alice->>Alice: Compute ss = X25519(xsk_c, xpk_s)<br/>Derive keys: HKDF-SHA256(ss, nonce_c || nonce_s) -> c2s, s2c

    Note over Alice,Bob: Step 6: Data Channel Established (820 B Wire Total, No Finished Confirmation)
    critical [VULN-3: GCM Nonce Reuse]
        Alice->>Alice: Vulnerable: Nonce counter resets to 0 across sessions (reveals XOR of plaintexts)<br/>Hardened: NonceManager enforces monotonic 96-bit counter and rekeying at 2^32 records
    end
    Alice->>Bob: EncryptedRecord(seq=0, nonce, AES-256-GCM(c2s, plaintext))

    critical [VULN-2: Replay Attack]
        Eve->>Bob: Replays captured EncryptedRecord(seq=0)<br/>Vulnerable: Bob accepts duplicate without sequence checking<br/>Hardened: ReplayGuard rejects duplicate seq=0 (emits REPLAY event)
    end
```

## Summary of Vulnerabilities & Hardening

| Vulnerability ID | Root Cause in `CLASSICAL-VULNERABLE` | Defensive Hardening in `CLASSICAL-HARDENED` & `HYBRID` |
| :--- | :--- | :--- |
| **`VULN-1` (Downgrade)** | `HandshakeConfig.skipSuiteSignature=true`: Server signature covers only key shares and nonces, leaving the offered suite list unauthenticated. | Full handshake transcript including client-offered suites is bound into the digital signature (`DowngradeGuard`). |
| **`VULN-2` (Replay)** | `HandshakeConfig.skipSequenceCheck=true`: Receiving secure channel accepts records without tracking sequence numbers. | `ReplayGuard` maintains strict monotonic sequence validation and a sliding-window replay filter. |
| **`VULN-3` (Nonce Reuse)** | `HandshakeConfig.unsafeNonceMode=true`: 96-bit AES-GCM nonce counter is reset to zero or reuses fixed IVs. | `NonceManager` guarantees strict monotonic increments, forbids IV reuse, and triggers rekeying before counter overflow. |
| **`VULN-4` (MITM)** | `HandshakeConfig.skipKeyPinning=true`: Client accepts any syntactically valid public key without pinning verification. | Strict public key pinning (`MitmGuard`) fails closed if the peer's public key does not match the pinned trust root. |
