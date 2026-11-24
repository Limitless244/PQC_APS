# Attack Execution & Defensive Guard Flows

This document details the exact execution flow of the five primary attacks evaluated in `attack-lab` and demonstrates where the defensive guards in `attack-engine` intercept and neutralize them.

---

## 1. Downgrade Attack vs `DowngradeGuard`

```mermaid
sequenceDiagram
    actor Client
    actor Attacker
    actor Server
    participant Guard as DowngradeGuard (in Client)
    participant Log as EventLog

    Client->>Attacker: ClientHello(suites=["HYBRID", "CLASSICAL"])
    Attacker->>Server: Stripped ClientHello(suites=["CLASSICAL"])
    Server->>Server: Compute transcript including suites=["CLASSICAL"]
    Server->>Server: Sign transcript with ML-DSA-65 / RSA-2048
    Server->>Client: ServerHello(chosenSuite="CLASSICAL", signature)
    Client->>Guard: Verify server signature against authentic transcript
    Note over Guard: Client calculates transcript using its original suites=["HYBRID", "CLASSICAL"]
    Guard->>Guard: Signature verification FAILS (Hash mismatch)
    Guard->>Log: record(DOWNGRADE, HIGH, "DowngradeGuard", suite, BLOCKED)
    Guard-->>Client: Throw SecurityException("Downgrade attack detected")
    Note over Client: Connection terminated fail-closed
```

---

## 2. Man-in-the-Middle (MITM) vs `MitmGuard`

```mermaid
sequenceDiagram
    actor Client
    actor Proxy as MITM Proxy (Eve)
    actor Server
    participant Guard as MitmGuard (in Client)
    participant Log as EventLog

    Client->>Proxy: ClientHello
    Proxy->>Server: ClientHello (Leg 1)
    Server->>Proxy: Authentic ServerHello with Server Key
    Proxy->>Proxy: Terminate Server leg; craft rogue ServerHello with Eve's key
    Proxy->>Client: Rogue ServerHello(Eve's Public Key, Eve's Signature)
    Client->>Guard: Validate server public key against pinned identity key
    Note over Guard: Check pinnedServerKey.equals(peerPublicKey)
    Guard->>Guard: Key mismatch! Untrusted key presented
    Guard->>Log: record(MITM, HIGH, "MitmGuard", suite, BLOCKED)
    Guard-->>Client: Throw SecurityException("Pinned key mismatch: rogue server detected")
    Note over Client: Handshake aborted immediately
```

---

## 3. Replay Attack vs `ReplayGuard`

```mermaid
sequenceDiagram
    actor Client
    actor Attacker
    actor Server
    participant Guard as ReplayGuard (in Server)
    participant Log as EventLog

    Client->>Server: EncryptedRecord(seq=0, ciphertext_A)
    Server->>Guard: validateStrictSequence(0, "C2S", suite)
    Guard->>Guard: seq == expectedNextSeq (0 == 0) -> expectedNextSeq = 1
    Server->>Server: Decrypt and process ciphertext_A

    Note over Attacker: Attacker captures EncryptedRecord(seq=0)
    Attacker->>Server: Replay EncryptedRecord(seq=0, ciphertext_A)
    Server->>Guard: validateStrictSequence(0, "C2S", suite)
    Note over Guard: Check: seq (0) < expectedNextSeq (1)
    Guard->>Log: record(REPLAY, HIGH, "ReplayGuard", suite, BLOCKED)
    Guard-->>Server: Throw SecurityException("Replay attack detected: sequence 0 already processed")
    Note over Server: Packet discarded; no duplicate state change
```

---

## 4. GCM Nonce Reuse vs `NonceManager`

```mermaid
sequenceDiagram
    actor Sender
    participant Guard as NonceManager
    participant Cipher as AesGcmCipher
    participant Log as EventLog

    Sender->>Guard: nextNonce()
    Guard->>Guard: Return nonce_0 (monotonic counter = 0)
    Sender->>Cipher: encrypt(key, nonce_0, plaintext_1) -> ct_1

    critical Attacker / Bug Attempts Nonce Reset
        Sender->>Guard: reset() or reuseNonce(nonce_0)
        Guard->>Guard: Check nonce cache / counter monotonicity
        Guard->>Log: record(NONCE_REUSE, HIGH, "NonceManager", suite, BLOCKED)
        Guard-->>Sender: Throw NonceReuseException("Nonce reuse prohibited")
    end

    critical 2^32 Boundary Rekey Enforcement
        Sender->>Guard: nextNonce() when counter >= 2^32 - 1
        Guard->>Log: record(NONCE_REUSE, HIGH, "NonceManager", suite, BLOCKED)
        Guard-->>Sender: Throw RekeyRequiredException("Channel rekey required")
    end
```

---

## 5. Ciphertext & Message Tampering vs `TamperGuard`

```mermaid
sequenceDiagram
    actor Client
    actor Attacker
    actor Server
    participant Guard as TamperGuard
    participant Log as EventLog

    Client->>Attacker: EncryptedRecord(seq=0, nonce, ciphertext)
    Note over Attacker: Attacker flips 1 bit in ciphertext (XOR 0x01)
    Attacker->>Server: EncryptedRecord(seq=0, nonce, tampered_ciphertext)
    Server->>Server: AesGcmCipher.decrypt(key, nonce, aad, tampered_ciphertext)
    Note over Server: AES-GCM GHASH tag verification fails (AEADBadTagException)
    Server->>Guard: handleAeadTampering(exception, seq=0, nonce, suite)
    Guard->>Log: record(TAMPER, HIGH, "TamperGuard", suite, BLOCKED, "AEAD tag mismatch...")
    Guard-->>Server: Return sanitized SecurityException("Record decryption failed")
    Note over Server: Network receives uniform error (zero oracle information leak)
```
