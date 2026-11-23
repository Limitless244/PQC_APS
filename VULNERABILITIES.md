# VULNERABILITIES.md — Phase 1 Intentional Weaknesses

> These vulnerabilities are **deliberately included** in the Phase 1 classical baseline.
> Phase 2 demonstrates attacks that exploit each one.
> Phase 4 fixes every weakness and shows the attacks failing.

---

## VULN-1 — Suite Downgrade Attack

| Property | Value |
|----------|-------|
| **Location** | `ClassicalHandshake.buildTranscript()` |
| **Config flag** | `HandshakeConfig.skipSuiteSignature = true` |
| **Phase 2 attacker** | `DowngradeAttacker.java` |

### What's wrong
The RSA signature in `ServerHello` covers only:
```
xpk_c || xpk_s || nonce_c || nonce_s
```
The **client's suite list** (`["HYBRID", "PQ_ONLY", "CLASSICAL"]`) is **not signed**.

### Attack
An on-path attacker intercepts `ClientHello`, removes `"HYBRID"` and `"PQ_ONLY"` from
the suite list leaving only `["CLASSICAL"]`, then forwards the modified message.
The server selects `CLASSICAL`, signs the transcript (which never included the suite
list), and the client's verification passes — because the original signature was
computed without the suite list anyway.

Both sides now use `CLASSICAL` even though the client wanted `HYBRID` or `PQ_ONLY`.

### Fix (Phase 4)
Set `skipSuiteSignature = false`. The server now includes the full suite list bytes
in the signed transcript. Any modification breaks the signature and the client aborts.

---

## VULN-2 — Replay Attack

| Property | Value |
|----------|-------|
| **Location** | `ClassicalSecureChannel.receive()` |
| **Config flag** | `HandshakeConfig.skipSequenceCheck = true` |
| **Phase 2 attacker** | `ReplayAttacker.java` |

### What's wrong
Each `EncryptedRecord` carries a `sequenceNumber`, but the receiver never checks
whether it equals the expected next sequence number. Any previously seen record with
a valid GCM tag can be injected again and will be accepted.

### Attack
1. Attacker captures record seq=0 (e.g., a "transfer £100" command).
2. Hours later, re-injects the exact same `EncryptedRecord` on the wire.
3. Server decrypts it successfully (the GCM key+nonce+tag are unchanged).
4. The command is executed a second time.

### Fix (Phase 4)
Set `skipSequenceCheck = false`. Receiver rejects any record whose `sequenceNumber`
is not strictly `expectedSeq`, and bumps the counter. Old records are rejected.

---

## VULN-3 — GCM Nonce Reuse

| Property | Value |
|----------|-------|
| **Location** | `ClassicalSecureChannel.buildNonce()` and `resetNonceCounterForTesting()` |
| **Config flag** | `HandshakeConfig.unsafeNonceMode = true` |
| **Phase 2 attacker** | `NonceReuseAttacker.java` |

### What's wrong
The GCM nonce is a simple counter that **starts at 0 on every `ClassicalSecureChannel`
construction**. If the same session key is ever reused across two channel instances
(e.g., key persistence + server restart), the same `(key, nonce)` pair appears twice.

### Why GCM nonce reuse is catastrophic
Given two ciphertexts `C1 = P1 ⊕ CTR_key(nonce)` and `C2 = P2 ⊕ CTR_key(nonce)`,
the XOR `C1 ⊕ C2 = P1 ⊕ P2` leaks the XOR of the two plaintexts.
Additionally, the GHASH authentication subkey `H` can be recovered, allowing the
attacker to forge arbitrary ciphertexts with valid tags.

### Attack
1. Capture `C1 = Enc(key, nonce=0, plaintext1)`.
2. Trigger a server restart (or use `resetNonceCounterForTesting()`).
3. Send a known plaintext, receive `C2 = Enc(key, nonce=0, known_plaintext)`.
4. `C1 ⊕ C2 = plaintext1 ⊕ known_plaintext` → recover `plaintext1`.

### Fix (Phase 4)
Set `unsafeNonceMode = false`. The counter is never reset, and the channel triggers
a rekeying (new ECDH exchange) before the counter approaches 2³².

---

## VULN-4 — Man-in-the-Middle via Missing Key Pinning

| Property | Value |
|----------|-------|
| **Location** | `ClassicalHandshake.clientHandshake()` |
| **Config flag** | `HandshakeConfig.skipKeyPinning = true` |
| **Phase 2 attacker** | `MitmAttacker.java` |

### What's wrong
When `skipKeyPinning = true`, the client calls `serverHandshake()` with
`pinnedServerKey = null` and **completely skips** the RSA signature verification.
The client trusts whatever public key the server (or an attacker) presents.

### Attack
1. Attacker sits between client and server (network MITM position).
2. Attacker generates their own RSA-2048 keypair.
3. Intercepts `ClientHello`, forwards to server.
4. Receives `ServerHello` from real server, intercepts it.
5. Replaces `xpk_s` with their own X25519 public key and replaces the
   signature with one made using their own RSA key.
6. Forwards the modified `ServerHello` to the client.
7. Client skips verification → accepts attacker's keypair.
8. Attacker now holds two separate sessions: client↔attacker and attacker↔server.
9. Attacker decrypts, reads, and optionally modifies all traffic.

### Fix (Phase 4)
Set `skipKeyPinning = false` and provide the real server's RSA public key
(distributed out-of-band, e.g., baked into a config file or certificate).
Any substituted key produces a signature that fails `RsaSigner.verify()`,
and the client aborts with a `SecurityException`.

---

## Summary Table

| ID | Vulnerability | Attack Class | Config Flag | Fixed in |
|----|--------------|-------------|-------------|---------|
| VULN-1 | Suite downgrade | Downgrade | `skipSuiteSignature` | Phase 4 |
| VULN-2 | Record replay | Replay | `skipSequenceCheck` | Phase 4 |
| VULN-3 | GCM nonce reuse | Nonce reuse | `unsafeNonceMode` | Phase 4 |
| VULN-4 | MITM / no pinning | MITM | `skipKeyPinning` | Phase 4 |
