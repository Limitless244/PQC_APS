# ATTACKS.md — Phase 2 Attack Lab: Exploitation of the Classical Baseline

This document provides a comprehensive analysis of the four cryptographic attacks implemented in the `attack-lab` module against the Phase 1 classical baseline. Each attack demonstrates a real-world vulnerability enabled by the intentional design weaknesses (VULN-1 through VULN-4), complete with step-by-step traces, concrete example values (shortened hex), and the planned Phase 4 mitigations.

---

## Attack 1: Cipher Suite Downgrade Attack

### 1. Plain-English Explanation
In a secure negotiation protocol (like TLS 1.3), the client sends a list of cryptographic suites it supports in order of preference (e.g. `[HYBRID, CLASSICAL]`). The server selects the strongest mutually supported suite. 

A **downgrade attack** occurs when an active, on-path adversary (man-in-the-middle) intercepts the client's handshake announcement, deletes the high-security or post-quantum suites, and forwards a doctored list (e.g. `[CLASSICAL]`). If the handshake does not cryptographically bind the offered suite list to the server's authentication signature, neither the client nor the server can detect that the list was tampered with. Both parties fall back to the weak algorithm suite without raising any security alarm.

### 2. Vulnerability Exploited
- **VULN-1**: `HandshakeConfig.skipSuiteSignature = true`.
- **Location**: `ClassicalHandshake.buildTranscript()`.
- **Root Cause**: The transcript over which the server calculates its digital signature contains `xpk_c`, `xpk_s`, `nonce_c`, and `nonce_s`, but **omits** `hello.suites()`.

### 3. Step-by-Step Trace with Example Values
```
[Client] Generates ephemeral key: xpk_c = 302a3005…
[Client] Proposes suites: [HYBRID, CLASSICAL]
[Client] Sends ClientHello -> Proxy (127.0.0.1:proxyPort)
    |
    |--> [Proxy Intercepts ClientHello]
         BEFORE: [HYBRID, CLASSICAL]
         Attacker strips "HYBRID"
         AFTER:  [CLASSICAL]
         Proxy forwards modified ClientHello -> Server (127.0.0.1:serverPort)
             |
             |--> [Server Receives Doctored ClientHello]
                  Server reads suites: [CLASSICAL]
                  Server chooses: "CLASSICAL"
                  Server computes ss = X25519(xsk_s, xpk_c) -> 80d02685…
                  Server builds transcript: xpk_c || xpk_s || nonce_c || nonce_s
                  [VULN-1: suite list is NOT in transcript]
                  Server signs transcript with RSA private key -> sig = 2acdec3d…
                  Server sends ServerHello(xpk_s=302a3005…, suite=CLASSICAL, sig=2acdec3d…) -> Proxy
                       |
                       |--> [Proxy Relays ServerHello to Client unchanged]
                            |
                            |--> [Client Receives ServerHello]
                                 Client builds transcript: xpk_c || xpk_s || nonce_c || nonce_s
                                 Client verifies sig with pinned server public key:
                                 verify(serverPk, transcript, sig) == TRUE!
                                 Client accepts handshake!
```
- **Console Output**:
  ```
  BEFORE: [HYBRID, CLASSICAL]  AFTER: [CLASSICAL]  Handshake accepted: true
  ```

### 4. Planned Phase 4 Defense
- Set `HandshakeConfig.skipSuiteSignature = false`.
- The transcript must include the exact canonical byte representation of `hello.suites()`.
- When an attacker alters the suite list, `hash(transcript_server) != hash(transcript_client)`. The client's signature verification will fail with `SecurityException`, aborting the connection before any application data is sent.

---

## Attack 2: Man-In-The-Middle (MITM) Eavesdropping Attack

### 1. Plain-English Explanation
In public-key cryptography, Diffie-Hellman key exchange provides forward secrecy, but DH keys alone do not provide **authentication**. Without authenticating who owns the public key, an attacker sitting on the network path between the client and server can intercept the connection, establish one encrypted channel with the client and another encrypted channel with the real server, and relay messages between them while reading or altering every byte in cleartext.

To prevent MITM, the client must verify the server's identity signature against a trusted ("pinned") public key. When a client operates in an "insecure" or testing mode that skips key pinning, it blindly trusts whichever public key is presented.

### 2. Vulnerability Exploited
- **VULN-4**: `HandshakeConfig.skipKeyPinning = true`.
- **Location**: `ClassicalHandshake.clientHandshake()`.
- **Root Cause**: The client bypasses `suite.signatureScheme().verify(...)`, accepting any arbitrary public key and signature sent by an on-path entity.

### 3. Step-by-Step Trace with Example Values
```
[Real Server] Listens on 127.0.0.1:serverPort with real server RSA keypair.
[Attacker Proxy] Listens on 127.0.0.1:proxyPort with attacker RSA keypair.

Leg 1: Client <---> Proxy (Fake Server)
  - Client connects to 127.0.0.1:proxyPort.
  - Proxy acts as server, sends attacker's ephemeral X25519 key and attacker's RSA signature.
  - [VULN-4 Active]: Client skips key pinning check!
  - Handshake 1 completes: Client <-> Proxy derive SessionKeys(c2s=48cf3691…, s2c=57f59193…).

Leg 2: Proxy (Fake Client) <---> Real Server
  - Proxy connects to Real Server on 127.0.0.1:serverPort.
  - Handshake 2 completes: Proxy <-> Real Server derive SessionKeys(c2s=d8d0bf00…, s2c=2346fd75…).

Data Phase (Eavesdropping & Relay):
  1. Client sends confidential record:
     Plaintext: "TRANSFER $50,000 FROM ACC-001 TO ACC-002"
     Encrypted with c2s=48cf3691… -> ciphertext sent to Proxy.
  2. Proxy decrypts ciphertext using c2s=48cf3691…:
     [MITM PROXY] Intercepted C->S: "TRANSFER $50,000 FROM ACC-001 TO ACC-002"
  3. Proxy re-encrypts the exact plaintext using c2s=d8d0bf00… -> sends to Real Server.
  4. Real Server decrypts using c2s=d8d0bf00…, processes transfer, and replies:
     Plaintext: "SERVER_ACK_TXN_ACCEPTED"
  5. Proxy decrypts server reply, logs it, re-encrypts with s2c=57f59193… -> sends to Client.
  6. Client decrypts reply. Both endpoints assume end-to-end confidentiality!
```

### 4. Planned Phase 4 Defense
- Enforce strict public key pinning (`skipKeyPinning = false`).
- In Phase 4, the client always verifies the transcript signature against the pinned server public key (and in Phase 3/4 with post-quantum ML-DSA-65 signatures).
- If an attacker substitutes their own key, `SignatureScheme.verify(pinnedKey, ...)` returns `false`, and the client throws `SecurityException: Server signature verification FAILED — possible MITM attack!`.

---

## Attack 3: Transaction Record Replay Attack

### 1. Plain-English Explanation
Authenticated encryption (such as AES-GCM) guarantees that ciphertext has not been tampered with. However, standard encryption does **not** automatically guarantee that a valid, unmodified ciphertext cannot be captured and transmitted a second time (or multiple times).

If a network eavesdropper captures an encrypted message instructing a server to "transfer 100", they can re-inject that exact same packet hours or days later. If the receiver does not track and enforce strictly incrementing sequence numbers, the receiver will decrypt the valid packet and execute the action again.

### 2. Vulnerability Exploited
- **VULN-2**: `HandshakeConfig.skipSequenceCheck = true`.
- **Location**: `ClassicalSecureChannel.receive()`.
- **Root Cause**: The receiver extracts the sequence number from `EncryptedRecord` and uses it as AAD, but never checks if `record.sequenceNumber() == expectedSeq`.

### 3. Step-by-Step Trace with Example Values
```
[Client] Establishes session keys with Server.
[Client] Sends Record 1:
         Sequence Number: 0
         Nonce: 000000000000000000000000 (12 bytes)
         Plaintext: "transfer 100"
         Ciphertext + Tag: 38536cbb…
         [Server] Receives record seq=0 -> Valid GCM tag -> Processed: "transfer 100" (#1)

[Client] Sends Record 2:
         Sequence Number: 1
         Nonce: 000000000000000000000001
         Plaintext: "check balance"
         [Server] Receives record seq=1 -> Valid GCM tag -> Processed: "check balance"

[Attacker] Re-injects captured Record 1 into the TCP socket:
         Sequence Number: 0  (Duplicate / Out-of-order!)
         Nonce: 000000000000000000000000
         Ciphertext + Tag: 38536cbb…
         [VULN-2 Active]: Server receives record seq=0.
         Server calculates AAD using seq=0.
         Tag verifies successfully because seq=0 matches original AAD!
         [Server] Processed: "transfer 100" (#2 - REPLAY ACCEPTED!)
```

### 4. Planned Phase 4 Defense
- Enforce strict sequence tracking (`skipSequenceCheck = false`).
- The receiver maintains an internal state variable `expectedSeq` (starting at 0).
- If `record.sequenceNumber() != expectedSeq`, the receiver drops the record, flags a replay attack security event, and terminates the session with:
  `SecurityException: Sequence number mismatch — possible replay! expected=2 got=0`.

---

## Attack 4: AES-GCM Nonce Reuse Keystream Leak

### 1. Plain-English Explanation
AES-GCM combines Counter Mode (CTR) for confidentiality with GHASH for authentication. In CTR mode, the block cipher encrypts a counter block derived from the nonce to generate a pseudo-random **keystream**, which is then XORed with the plaintext:
$$\text{Ciphertext} = \text{Plaintext} \oplus \text{Keystream}$$

A fundamental rule of CTR mode is that a `(key, nonce)` pair must **never** be used more than once. If two distinct plaintexts ($P_1$ and $P_2$) are encrypted under the same key and nonce, the keystream is identical:
$$C_1 = P_1 \oplus \text{Keystream}$$
$$C_2 = P_2 \oplus \text{Keystream}$$

XORing the two ciphertexts together causes the keystream to cancel out entirely:
$$C_1 \oplus C_2 = (P_1 \oplus \text{Keystream}) \oplus (P_2 \oplus \text{Keystream}) = P_1 \oplus P_2$$

If the attacker knows or can guess $P_1$ (e.g. standard file headers, known API requests, predictable transaction templates), they can immediately recover $P_2$:
$$P_2 = (C_1 \oplus C_2) \oplus P_1$$
The secret message is revealed completely without finding the AES key!

### 2. Vulnerability Exploited
- **VULN-3**: `HandshakeConfig.unsafeNonceMode = true`.
- **Location**: `ClassicalSecureChannel.buildNonce()` and `resetNonceCounterForTesting()`.
- **Root Cause**: The nonce counter resets to 0 across restarts or instances while using the same session key, causing identical nonces to encrypt multiple plaintexts.

### 3. Step-by-Step Trace with Example Values
```
Session Key: 141831e2… (32 bytes AES key)
Reused Nonce: 000000000000000000000000 (12 bytes)

1. Known Plaintext P1:
   "TRANSFER $100 TO ALICE [TXN-001]"
   Ciphertext C1 (body): 38536cbb…

2. Target Secret Plaintext P2:
   "TRANSFER $950 TO EVE   [TXN-002]"
   Ciphertext C2 (body): 38536cbb…

3. Keystream Cancellation:
   C1 ⊕ C2 == P1 ⊕ P2 ? TRUE!
   (XOR difference of ciphertexts matches XOR difference of plaintexts)

4. Plaintext Recovery:
   Recovered_P2 = (C1 ⊕ C2) ⊕ P1
   Result: "TRANSFER $950 TO EVE   [TXN-002]"
   Secret plaintext successfully recovered!
```

### 4. Planned Phase 4 Defense
- Enforce strict `CounterNonceManager` (`unsafeNonceMode = false`).
- Maintain a monotonic 64-bit invocation counter.
- Hard limit of $2^{32}$ records per session key.
- Force automatic session rekeying (generating fresh ephemeral keys via hybrid KEX) before counter overflow can occur.
- Reject any attempt to reset or rewind the nonce counter under the same key.

---

## Summary Matrix

| Attack Name | Vulnerability | Metric / Artifact | Baseline Result (Phase 2) | Hardened Target (Phase 4) |
|---|---|---|---|---|
| **Downgrade Attack** | VULN-1 | `BEFORE: [HYBRID, CLASSICAL] AFTER: [CLASSICAL]` | **Accepted** (Silently downgraded) | **Rejected** (Signature verification fails) |
| **MITM Attack** | VULN-4 | Plaintext intercepted in both directions | **Accepted** (Full eavesdrop) | **Rejected** (Pinned key check fails) |
| **Replay Attack** | VULN-2 | Duplicate sequence 0 record | **Accepted** (Duplicate processed) | **Rejected** (Sequence mismatch error) |
| **GCM Nonce Reuse** | VULN-3 | $C_1 \oplus C_2 = P_1 \oplus P_2 \implies P_2$ | **Accepted** (Plaintext recovered) | **Rejected** (Counter overflow prevention / rekey) |
