package com.pqcaps.common;

import java.io.Serial;
import java.io.Serializable;

/**
 * Second message of the handshake: Server -> Client.
 *
 * <p>The server selects a cipher suite, provides its ephemeral public key shares
 * (X25519 public key and/or ML-KEM ciphertext), a fresh nonce, and a digital signature
 * over the handshake transcript.
 *
 * @param xpk_s       server's ephemeral X25519 public key, or null for PQ_ONLY
 * @param ct          ML-KEM-768 encapsulation ciphertext (~1088 bytes), or null for CLASSICAL
 * @param chosenSuite the suite the server selected from the client's list
 * @param nonce_s     32-byte cryptographically random server nonce
 * @param signature   server's signature over the handshake transcript (RSA or ML-DSA-65)
 */
public record ServerHello(
        byte[]  xpk_s,
        byte[]  ct,
        String  chosenSuite,
        byte[]  nonce_s,
        byte[]  signature
) implements Serializable {

    @Serial
    private static final long serialVersionUID = 2L;

    /**
     * Backward-compatible constructor for Phase 1 & 2 classical baseline.
     */
    public ServerHello(byte[] xpk_s, String chosenSuite, byte[] nonce_s, byte[] signature) {
        this(xpk_s, null, chosenSuite, nonce_s, signature);
    }
}
