# Post-Quantum Hybrid Handshake Protocol (`HYBRID`)

Implemented in `com.pqcaps.channel.HybridHandshake` (`secure-channel` module). Combines classical Curve25519 Diffie-Hellman with NIST FIPS 203 ML-KEM-768 for quantum-resistant forward secrecy, authenticated by NIST FIPS 204 ML-DSA-65 signatures.

```mermaid
sequenceDiagram
    autonumber
    actor Alice as Client (Alice)
    participant Net as Network / Socket
    actor Bob as Server (Bob)

    Note over Alice,Bob: Step 1: Ephemeral Key Generation
    Alice->>Alice: Generate ephemeral X25519 keypair (xsk_c, xpk_c)<br/>Generate ephemeral ML-KEM-768 keypair (ksk_c, kpk_c)<br/>Generate 32-byte client nonce (nonce_c)

    Note over Alice,Bob: Step 2: ClientHello (1,356 Bytes)
    Alice->>Net: ClientHello(xpk_c [32 B], kpk_c [1,184 B], suites=["HYBRID"], nonce_c [32 B])
    Net->>Bob: Deliver ClientHello

    Note over Bob: Step 3: Key Encapsulation & Derivation
    Bob->>Bob: Generate ephemeral X25519 keypair (xsk_s, xpk_s)<br/>Compute ss1 = X25519(xsk_s, xpk_c) [32 B]<br/>Encapsulate ML-KEM: (ct, ss2) = ML-KEM-768.encapsulate(kpk_c) [ct: 1,088 B, ss2: 32 B]<br/>Generate 32-byte server nonce (nonce_s)
    Bob->>Bob: Compute transcript = ClientHello || xpk_s || ct || "HYBRID" || nonce_s<br/>transcriptHash = SHA-256(transcript)<br/>Derive keys: HybridKeySchedule.deriveSessionKeys("HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash)<br/>-> c2s [32 B], s2c [32 B], finishedKey [32 B]
    Bob->>Bob: Sign transcript: signature = ML-DSA-65.sign(serverSigningKey, transcript) [3,309 B]

    Note over Alice,Bob: Step 4: ServerHello (4,488 Bytes)
    Bob->>Net: ServerHello(xpk_s [32 B], ct [1,088 B], chosenSuite="HYBRID", nonce_s [32 B], signature [3,309 B])
    Net->>Alice: Deliver ServerHello

    Note over Alice: Step 5: Verification & Key Derivation
    Alice->>Alice: Verify signature: ML-DSA-65.verify(pinnedServerKey, transcript, signature)<br/>[Aborts immediately if unpinned or signature invalid (MitmGuard / DowngradeGuard)]
    Alice->>Alice: Compute ss1 = X25519(xsk_c, xpk_s) [32 B]<br/>Decapsulate ss2 = ML-KEM-768.decapsulate(ksk_c, ct) [32 B]<br/>Derive keys: HybridKeySchedule.deriveSessionKeys("HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash)<br/>-> c2s [32 B], s2c [32 B], finishedKey [32 B]

    Note over Alice,Bob: Step 6: Client Finished Message (127 Bytes)
    Alice->>Alice: clientVerifyData = HMAC-SHA256(finishedKey, transcriptHash)
    Alice->>Net: FinishedMessage(clientVerifyData)
    Net->>Bob: Deliver FinishedMessage
    Bob->>Bob: Verify clientVerifyData via HybridKeySchedule.verifyFinished()

    Note over Alice,Bob: Step 7: Server Finished Message (127 Bytes)
    Bob->>Bob: serverTranscriptHash = SHA-256(transcriptHash || clientVerifyData)<br/>serverVerifyData = HMAC-SHA256(finishedKey, serverTranscriptHash)
    Bob->>Net: FinishedMessage(serverVerifyData)
    Net->>Alice: Deliver FinishedMessage
    Alice->>Alice: Verify serverVerifyData via HybridKeySchedule.verifyFinished()

    Note over Alice,Bob: Step 8: Secure Data Channel Established (6,433 B Total Wire)
    Alice->>Net: EncryptedRecord(seq=0, nonce, AES-256-GCM(c2s, plaintext))
    Net->>Bob: Verified & Decrypted by Bob
```

## Verified Code Cross-Check

- **Classes Involved**:
  - `com.pqcaps.channel.HybridHandshake` (`clientHandshake`, `serverHandshake`)
  - `com.pqcaps.classical.X25519KeyExchange` (`generateKeyPair`, `deriveSharedSecret`)
  - `com.pqcaps.kex.MlKemKeyExchange` (`generateKeyPair`, `encapsulate`, `decapsulate`)
  - `com.pqcaps.auth.MlDsaSignatureScheme` (`sign`, `verify`)
  - `com.pqcaps.kex.HybridKeySchedule` (`deriveSessionKeys`, `computeFinished`, `verifyFinished`)
  - `com.pqcaps.channel.FinishedMessage`
- **Wire Overhead**: Total serialized socket bytes = **6,433 B** (1,504 B ClientHello + 4,675 B ServerHello + 127 B Client Finished + 127 B Server Finished). Unframed cryptographic payload = **6,098 B**.
