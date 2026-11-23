package com.pqcaps.common;

/**
 * A named bundle of three cryptographic algorithms that together implement
 * a complete secure-channel protocol: key exchange, authentication, and
 * symmetric encryption.
 *
 * <p>Callers obtain a suite from a registry (e.g. {@code SuiteRegistry.get("CLASSICAL")})
 * and pass it to the handshake; the handshake never references a concrete class.
 * This is the "crypto-agility" pattern: swapping algorithms requires changing only
 * the suite string in configuration.
 *
 * <p>Current suites:
 * <ul>
 *   <li>"CLASSICAL" — X25519 + RSA-2048 + AES-256-GCM (Phase 1 baseline)</li>
 *   <li>"HYBRID"    — X25519 + ML-KEM-768 + ML-DSA-65 + AES-256-GCM (Phase 3)</li>
 *   <li>"PQ_ONLY"   — ML-KEM-768 + ML-DSA-65 + AES-256-GCM (Phase 3)</li>
 * </ul>
 */
public interface CryptoSuite {

    /** Short identifier sent in {@link ClientHello} and {@link ServerHello}. */
    String id();

    /** Key-exchange algorithm (ephemeral, provides forward secrecy). */
    KeyExchange keyExchange();

    /** Signature algorithm (long-lived server identity). */
    SignatureScheme signatureScheme();

    /** Symmetric AEAD cipher for the record layer. */
    AeadCipher aeadCipher();
}
