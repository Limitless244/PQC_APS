# PQC-APS System Architecture & Module Dependencies

```mermaid
graph TD
    classDef core fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef pqc fill:#ede7f6,stroke:#512da8,stroke-width:2px;
    classDef sec fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef atk fill:#ffebee,stroke:#c62828,stroke-width:2px;
    classDef ui fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef data fill:#f5f5f5,stroke:#616161,stroke-width:1px,stroke-dasharray: 5 5;

    subgraph "Parent Module"
        POM["pqc-aps<br/>(Maven Reactor Parent)"]:::core
    end

    subgraph "Cryptographic Primitives & Agility"
        COMMON["common<br/>(Records, SessionKeys, Config)"]:::core
        CLASSICAL["classical<br/>(X25519, RSA-2048, AES-GCM)"]:::core
        HYBRID_KEX["hybrid-kex<br/>(ML-KEM-768 + X25519)"]:::pqc
        PQ_AUTH["pq-auth<br/>(ML-DSA-65 Signatures)"]:::pqc
        AGILITY["crypto-agility<br/>(AlgorithmRegistry, Providers)"]:::pqc
    end

    subgraph "Protocol & Secure Channel"
        SEC_CHANNEL["secure-channel<br/>(HybridHandshake, Channel)"]:::sec
    end

    subgraph "Attack Lab & Prevention Engine"
        ATTACK_ENGINE["attack-engine<br/>(8 Defensive Guards & EventLog)"]:::atk
        ATTACK_LAB["attack-lab<br/>(15-Cell SecurityMatrixRunner)"]:::atk
        SCANNER["crypto-scanner<br/>(Static Rule Engine & AST)"]:::atk
    end

    subgraph "Evaluation & Web UI"
        DASHBOARD["benchmark-dashboard<br/>(Spring Boot Backend & Chart.js)"]:::ui
    end

    subgraph "Evaluation Data Files (data/)"
        D_TEST["test-summary.json"]:::data
        D_ATK["attack-results.json"]:::data
        D_BENCH["benchmark-results.json"]:::data
        D_SCAN["scan-report-*.json"]:::data
        D_EVT["detection-events.jsonl"]:::data
    end

    %% Dependencies
    POM --> COMMON
    POM --> CLASSICAL
    POM --> AGILITY
    POM --> SCANNER
    POM --> HYBRID_KEX
    POM --> PQ_AUTH
    POM --> SEC_CHANNEL
    POM --> ATTACK_ENGINE
    POM --> ATTACK_LAB
    POM --> DASHBOARD

    CLASSICAL --> COMMON
    AGILITY --> COMMON
    HYBRID_KEX --> COMMON
    HYBRID_KEX --> CLASSICAL
    PQ_AUTH --> COMMON
    SEC_CHANNEL --> COMMON
    SEC_CHANNEL --> CLASSICAL
    SEC_CHANNEL --> HYBRID_KEX
    SEC_CHANNEL --> PQ_AUTH

    ATTACK_ENGINE --> COMMON
    ATTACK_ENGINE --> SEC_CHANNEL
    ATTACK_LAB --> COMMON
    ATTACK_LAB --> CLASSICAL
    ATTACK_LAB --> SEC_CHANNEL
    ATTACK_LAB --> ATTACK_ENGINE

    DASHBOARD --> COMMON
    DASHBOARD --> CLASSICAL
    DASHBOARD --> SEC_CHANNEL
    DASHBOARD --> ATTACK_ENGINE
    DASHBOARD --> ATTACK_LAB
    DASHBOARD --> SCANNER

    %% Data connections
    ATTACK_LAB -.->|generates| D_ATK
    ATTACK_ENGINE -.->|appends| D_EVT
    SCANNER -.->|generates| D_SCAN
    DASHBOARD -.->|benchmarks generate| D_BENCH
    DASHBOARD -.->|reads all| D_TEST
    DASHBOARD -.->|reads all| D_ATK
    DASHBOARD -.->|reads all| D_BENCH
    DASHBOARD -.->|reads all| D_SCAN
    DASHBOARD -.->|reads all| D_EVT
```

## Module Responsibilities

1. **`pqc-aps`**: Reactor root aggregator managing dependencies (Bouncy Castle 1.80, Spring Boot 3.3.4, JMH 1.37).
2. **`common`**: Protocol data objects (`EncryptedRecord`, `SessionKeys`, `HandshakeConfig`, `DataPaths`).
3. **`classical`**: Classical baseline algorithms: Curve25519 ECDH (`X25519KeyExchange`), PKCS#1 v1.5 (`RsaSignatureScheme`), AES-256-GCM (`AesGcmCipher`).
4. **`crypto-agility`**: Dynamic cryptographic agility registry (`AlgorithmRegistry`, `CryptoSuiteFactory`).
5. **`crypto-scanner`**: Static AST/regex scanning engine with YAML rule registry detecting hardcoded secrets and post-quantum readiness.
6. **`hybrid-kex`**: Hybrid key encapsulation mechanism combining classical X25519 with NIST FIPS 203 ML-KEM-768 (`HybridKeySchedule`, `HybridKeyExchange`).
7. **`pq-auth`**: Post-quantum digital signature scheme implementing NIST FIPS 204 ML-DSA-65 (`MlDsaSignatureScheme`).
8. **`secure-channel`**: Complete 8-step hybrid protocol handshake with mutual key confirmation (`HybridHandshake`, `ClassicalSecureChannel`).
9. **`attack-engine`**: 8 real-time defensive guards (`DowngradeGuard`, `MitmGuard`, `ReplayGuard`, `NonceManager`, `TamperGuard`, `KeyReuseGuard`, `RandomnessGuard`, `TimingGuard`) and persistent `EventLog`.
10. **`attack-lab`**: Active offensive test harness executing the 15-cell evaluation matrix (`SecurityMatrixRunner`, standalone attack tests).
11. **`benchmark-dashboard`**: High-performance visualization dashboard serving live telemetry, benchmark data, and the simulated chat interface (`DashboardDataService`, `ChatDemoService`).
