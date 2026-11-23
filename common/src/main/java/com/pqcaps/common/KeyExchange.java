package com.pqcaps.common;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Contract for an asymmetric key-exchange algorithm.
 *
 * <p>Phase 1 implementation: {@code X25519KeyExchange} (classical DH).
 * Phase 3 will add {@code MlKemKeyExchange} (post-quantum KEM) alongside this.
 *
 * <p><b>Why an interface?</b> The handshake logic in {@code ClassicalHandshake}
 * never hardcodes "X25519" — it always calls through this interface. Swapping the
 * algorithm later requires only changing which implementation is injected.
 */
public interface KeyExchange {

    /**
     * Generates a fresh ephemeral keypair for one session.
     * <em>Always use a new keypair per session — reusing breaks forward secrecy.</em>
     *
     * @return a fresh keypair; the public key will be sent to the peer
     */
    KeyPair generateKeyPair();

    /**
     * Derives the shared secret from our private key and the peer's public key.
     * The raw output must be fed through a KDF before use as an encryption key.
     *
     * <p>Callers MUST zero the returned array with {@code Arrays.fill(ss, (byte)0)}
     * immediately after feeding it to the KDF.
     *
     * @param sk     our ephemeral private key
     * @param peerPk the peer's ephemeral public key (from the wire)
     * @return raw shared secret bytes (never use directly as a key)
     */
    byte[] deriveSharedSecret(PrivateKey sk, PublicKey peerPk);

    /**
     * Reconstructs a {@link PublicKey} from its encoded (SubjectPublicKeyInfo DER) form.
     * This is the inverse of {@code publicKey.getEncoded()}.
     *
     * @param encoded DER-encoded public key bytes received from the peer
     * @return the decoded public key ready for {@link #deriveSharedSecret}
     * @throws IllegalArgumentException if the bytes are not a valid key for this algorithm
     */
    PublicKey decodePublicKey(byte[] encoded);
}
