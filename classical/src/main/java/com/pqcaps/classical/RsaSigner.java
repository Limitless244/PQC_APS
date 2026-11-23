package com.pqcaps.classical;

import com.pqcaps.common.SignatureScheme;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA-2048 digital signatures using SHA256withRSA.
 *
 * <p>RSA is used here as the server's long-lived identity key: the server signs
 * the handshake transcript and the client verifies against a pinned copy of the
 * server's public key.
 *
 * <p><b>Why RSA-2048 is quantum-vulnerable</b>: Shor's algorithm factors large
 * integers in polynomial time. RSA-2048 provides ~112 bits of classical security
 * but zero bits of post-quantum security. NIST recommends at least RSA-3072 for
 * new classical deployments; Phase 3 replaces this with ML-DSA-65.
 *
 * <p><b>Key-size justification</b>: 2048 bits is used intentionally as the
 * "weak classical" baseline (the crypto-scanner in Phase 5 will flag it).
 */
public final class RsaSigner implements SignatureScheme {

    private static final String SIG_ALG  = "SHA256withRSA";
    private static final int    KEY_BITS = 2048; // intentionally below NIST 3072 recommendation

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(KEY_BITS, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    /**
     * Signs {@code data} with the RSA private key.
     *
     * <p>{@code SHA256withRSA} internally hashes the data with SHA-256 before
     * signing — we do NOT pre-hash here to avoid double-hashing.
     */
    @Override
    public byte[] sign(PrivateKey sk, byte[] data) {
        try {
            Signature sig = Signature.getInstance(SIG_ALG);
            sig.initSign(sk, new SecureRandom());
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException("RSA sign failed", e);
        }
    }

    /**
     * Verifies the RSA signature. Returns {@code false} rather than throwing on
     * verification failure so callers can distinguish auth failures from exceptions.
     */
    @Override
    public boolean verify(PublicKey pk, byte[] data, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(SIG_ALG);
            sig.initVerify(pk);
            sig.update(data);
            return sig.verify(signature);
        } catch (SignatureException | InvalidKeyException e) {
            // Verification failed — not a programming error, expected in attack scenarios
            return false;
        } catch (Exception e) {
            throw new IllegalStateException("RSA verify failed unexpectedly", e);
        }
    }

    @Override
    public PublicKey decodePublicKey(byte[] encoded) {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot decode RSA public key", e);
        }
    }
}
