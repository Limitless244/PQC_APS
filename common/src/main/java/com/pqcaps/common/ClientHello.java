package com.pqcaps.common;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

/**
 * First message of the handshake: Client -> Server.
 *
 * <p>The client announces which cipher suites it supports and provides its
 * ephemeral key shares (X25519 and/or ML-KEM-768) plus a fresh random nonce.
 *
 * @param xpk_c   client's ephemeral X25519 public key (SubjectPublicKeyInfo DER), or null for PQ_ONLY
 * @param kpk_c   client's ephemeral ML-KEM-768 public key (SubjectPublicKeyInfo DER), or null for CLASSICAL
 * @param suites  ordered list of suite IDs the client supports, most-preferred first
 * @param nonce_c 32-byte cryptographically random client nonce
 */
public record ClientHello(
        byte[]       xpk_c,
        byte[]       kpk_c,
        List<String> suites,
        byte[]       nonce_c
) implements Serializable {

    @Serial
    private static final long serialVersionUID = 2L;

    /**
     * Backward-compatible constructor for Phase 1 & 2 classical baseline.
     */
    public ClientHello(byte[] xpk_c, List<String> suites, byte[] nonce_c) {
        this(xpk_c, null, suites, nonce_c);
    }
}
