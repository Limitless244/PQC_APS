package com.pqcaps.classical;

import com.pqcaps.common.KeyExchange;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ephemeral X25519 key exchange using the JDK's XDH provider.
 *
 * <p>X25519 is an elliptic-curve Diffie-Hellman protocol on Curve25519. It is
 * faster than RSA and NIST-P curves, produces 32-byte shared secrets, and has
 * a simple, constant-time scalar-multiplication implementation in the JDK.
 *
 * <p><b>Handshake trace</b> (Phase 1):
 * <pre>
 * Client:
 *   kp_c = generateKeyPair()          xpk_c = 44bytes DER
 *
 * Server:
 *   kp_s = generateKeyPair()          xpk_s = 44bytes DER
 *   ss   = deriveSharedSecret(xsk_s, xpk_c)   → 32 bytes
 *
 * Client:
 *   ss   = deriveSharedSecret(xsk_c, xpk_s)   → same 32 bytes ✓
 * </pre>
 *
 * <p><b>Why X25519 is quantum-vulnerable</b>: Shor's algorithm can solve the
 * discrete-logarithm problem on elliptic curves in polynomial time on a large
 * enough quantum computer. Phase 3 adds ML-KEM-768 alongside X25519 in a hybrid
 * scheme so that security is maintained even if one component is broken.
 */
public final class X25519KeyExchange implements KeyExchange {

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
            // NamedParameterSpec.X25519 selects Curve25519 within the XDH family
            kpg.initialize(NamedParameterSpec.X25519, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("X25519 keypair generation failed", e);
        }
    }

    @Override
    public byte[] deriveSharedSecret(PrivateKey sk, PublicKey peerPk) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(sk);
            // last=true: X25519 has only one phase
            ka.doPhase(peerPk, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new IllegalStateException("X25519 DH failed", e);
        }
    }

    /**
     * Reconstructs an X25519 public key from its SubjectPublicKeyInfo DER encoding.
     * This is what {@code publicKey.getEncoded()} produces — 44 bytes for X25519.
     */
    @Override
    public PublicKey decodePublicKey(byte[] encoded) {
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot decode X25519 public key", e);
        }
    }
}
