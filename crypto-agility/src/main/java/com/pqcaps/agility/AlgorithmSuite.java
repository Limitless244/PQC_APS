package com.pqcaps.agility;

/**
 * Algorithm suite selector.
 *
 * <p>All algorithm identifiers flow through this enum. No module ever
 * hardcodes a string like "ML-KEM-768" — it always reads from {@link SuiteConfig}.
 * This makes migrating to a new algorithm (e.g. ML-KEM-1024) a one-line change
 * in {@code suites.yaml} without touching any crypto code.
 *
 * <p>Suites:
 * <ul>
 *   <li>{@link #CLASSICAL}  — X25519 KEM, ECDSA/RSA-2048 auth, AES-256-GCM</li>
 *   <li>{@link #HYBRID}     — X25519 + ML-KEM-768, ML-DSA-65, AES-256-GCM</li>
 *   <li>{@link #PQ_ONLY}    — ML-KEM-768 only, ML-DSA-65, AES-256-GCM</li>
 * </ul>
 */
public enum AlgorithmSuite {

    /**
     * Classical-only suite — vulnerable to Shor's algorithm on a sufficiently
     * powerful quantum computer. Provided as a baseline for comparison only.
     */
    CLASSICAL,

    /**
     * Hybrid suite — combines X25519 (classical) with ML-KEM-768 (post-quantum).
     * Secure against both classical and quantum attackers simultaneously.
     * <b>This is the recommended suite for the demo.</b>
     */
    HYBRID,

    /**
     * Post-quantum-only suite — relies solely on ML-KEM-768 / ML-DSA-65.
     * No classical component; forward-secure even without X25519.
     */
    PQ_ONLY;
}
