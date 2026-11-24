# Post-Quantum Hybrid Key Schedule & Combiner Architecture

Implemented in `com.pqcaps.kex.HybridKeySchedule` (`hybrid-kex` module). Combines the classical Diffie-Hellman secret (`ss1`) and the post-quantum ML-KEM secret (`ss2`) into symmetric session keys and key confirmation keys.

```mermaid
flowchart TD
    classDef secret fill:#ffe0b2,stroke:#e65100,stroke-width:2px;
    classDef public fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef crypto fill:#ede7f6,stroke:#4a148c,stroke-width:2px;
    classDef key fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px;

    SS1["Classical Shared Secret (ss1)<br/>X25519(xsk, xpk) [32 Bytes]"]:::secret
    SS2["Post-Quantum Shared Secret (ss2)<br/>ML-KEM-768(ksk, ct) [32 Bytes]"]:::secret

    IKM["Input Keying Material (IKM)<br/>ss1 || ss2 [64 Bytes]"]:::secret
    SS1 -->|Concat| IKM
    SS2 -->|Concat| IKM

    NONCE_C["Client Nonce (nonce_c) [32 B]"]:::public
    NONCE_S["Server Nonce (nonce_s) [32 B]"]:::public
    SALT["HKDF Salt<br/>nonce_c || nonce_s [64 Bytes]"]:::public
    NONCE_C -->|Concat| SALT
    NONCE_S -->|Concat| SALT

    PRK["Pseudorandom Key (PRK)<br/>HMAC-SHA256(Salt, IKM) [32 Bytes]"]:::crypto
    SALT -->|HKDF-Extract| PRK
    IKM -->|HKDF-Extract| PRK

    TRANSCRIPT["Handshake Transcript Hash<br/>SHA-256(ClientHello || ServerHello) [32 B]"]:::public
    INFO["HKDF Info Context<br/>'pqcaps/v1/HYBRID' || transcriptHash [48 B]"]:::public
    TRANSCRIPT --> INFO

    OKM["Output Keying Material (OKM)<br/>HKDF-Expand(PRK, Info, 96 Bytes)"]:::crypto
    PRK -->|HKDF-Expand| OKM
    INFO -->|HKDF-Expand| OKM

    C2S["clientToServer (c2s)<br/>OKM[0..31] (AES-256 Key)"]:::key
    S2C["serverToClient (s2c)<br/>OKM[32..63] (AES-256 Key)"]:::key
    FIN["finishedKey<br/>OKM[64..95] (HMAC Key)"]:::key

    OKM -->|Bytes 0..31| C2S
    OKM -->|Bytes 32..63| S2C
    OKM -->|Bytes 64..95| FIN

    FIN_CLIENT["Client Finished VerifyData<br/>HMAC-SHA256(finishedKey, transcriptHash) [32 B]"]:::public
    FIN_SERVER["Server Finished VerifyData<br/>HMAC-SHA256(finishedKey, SHA-256(transcriptHash || clientFinished)) [32 B]"]:::public

    FIN --> FIN_CLIENT
    TRANSCRIPT --> FIN_CLIENT
    FIN --> FIN_SERVER
    FIN_CLIENT --> FIN_SERVER
```

## Dual-PRK Security & The Hybrid Guarantee

The hybrid key combiner guarantees that the resulting session keys are secure as long as **at least one** of the underlying key exchange mechanisms remains uncompromised:

$$\text{Security}(\text{Hybrid}) \ge \max\left(\text{Security}(\text{X25519}), \text{Security}(\text{ML-KEM-768})\right)$$

### 1. Why Changing Either Shared Secret Completely Changes the Derived Keys
HKDF-Extract computes:
$$\text{PRK} = \text{HMAC-SHA256}(\text{Salt}, \text{ss}_1 \parallel \text{ss}_2)$$

Due to the strict avalanche effect of SHA-256:
- Modifying even a single bit of $\text{ss}_1$ (e.g. if classical Diffie-Hellman is altered or replaced) causes every bit of $\text{PRK}$ to change with probability $\approx 0.5$.
- Modifying even a single bit of $\text{ss}_2$ (e.g. if ML-KEM encapsulation is altered) likewise causes every bit of $\text{PRK}$ to change completely.
- Because $\text{OKM} = \text{HKDF-Expand}(\text{PRK}, \text{Info}, 96)$ expands $\text{PRK}$, all three derived keys (`c2s`, `s2c`, and `finishedKey`) are completely uncorrelated with prior keys if either secret changes.

### 2. Concrete Verification via Test Suite
This property is formally tested in `com.pqcaps.kex.HybridKeyScheduleTest` / `HybridKeyDerivationTest`:
- **Test 1**: Holding $\text{ss}_1$ constant and flipping one bit in $\text{ss}_2$ yields derived keys with zero byte correlation.
- **Test 2**: Holding $\text{ss}_2$ constant and flipping one bit in $\text{ss}_1$ yields derived keys with zero byte correlation.
- **Test 3**: An attacker who records the session and breaks X25519 using Shor's algorithm on a quantum computer in 2035 cannot derive $\text{PRK}$ or recover any plaintext because $\text{ss}_2$ (protected by the hardness of Module Learning with Errors) remains confidential.
