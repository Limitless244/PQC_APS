package com.pqcaps.common;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Contract for a digital signature algorithm.
 *
 * <p>Phase 1 implementation: {@code RsaSigner} (RSA-2048, SHA256withRSA).
 * Phase 3 will replace this with {@code MlDsaSigner} (ML-DSA-65 / FIPS 204).
 *
 * <p>The server uses this interface to sign the handshake transcript so the
 * client can authenticate the server's identity and detect MITM attacks.
 */
public interface SignatureScheme {

    /**
     * Generates a long-lived server identity keypair.
     * Unlike {@link KeyExchange#generateKeyPair()}, this keypair persists across
     * sessions — it represents the server's identity.
     *
     * @return a new keypair; the public key is distributed to clients as a
     *         "pinned" trust anchor
     */
    KeyPair generateKeyPair();

    /**
     * Signs {@code data} with the server's private key.
     *
     * @param sk   the server's private key
     * @param data the bytes to sign (typically a transcript hash)
     * @return the signature; send this to the client inside {@link ServerHello}
     */
    byte[] sign(PrivateKey sk, byte[] data);

    /**
     * Verifies a signature against the pinned server public key.
     *
     * @param pk        the pinned server public key
     * @param data      the signed bytes (must be rebuilt identically by the client)
     * @param signature the signature received in {@link ServerHello}
     * @return {@code true} if the signature is valid, {@code false} otherwise
     */
    boolean verify(PublicKey pk, byte[] data, byte[] signature);

    /**
     * Reconstructs a {@link PublicKey} from its encoded form.
     *
     * @param encoded SubjectPublicKeyInfo DER-encoded bytes
     * @return the decoded public key
     */
    PublicKey decodePublicKey(byte[] encoded);
}
