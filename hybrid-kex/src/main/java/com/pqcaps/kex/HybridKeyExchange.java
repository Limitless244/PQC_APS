package com.pqcaps.kex;

import com.pqcaps.classical.X25519KeyExchange;
import com.pqcaps.common.KemKeyExchange.EncapsulationResult;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Orchestrates hybrid key exchange by combining classical Diffie-Hellman
 * ({@link X25519KeyExchange}) with post-quantum KEM ({@link MlKemKeyExchange}).
 *
 * <p>Design Principle (Hybrid Security):
 * The hybrid scheme is secure as long as AT LEAST ONE of the underlying algorithms remains unbroken:
 * <ul>
 *   <li>If ML-KEM is broken by future cryptanalysis, X25519 protects against classical attackers.</li>
 *   <li>If X25519 is broken by Shor's algorithm on a quantum computer, ML-KEM protects the session key.</li>
 * </ul>
 */
public final class HybridKeyExchange {

    private final X25519KeyExchange classicalKex;
    private final MlKemKeyExchange pqKem;

    public HybridKeyExchange() {
        this.classicalKex = new X25519KeyExchange();
        this.pqKem = new MlKemKeyExchange();
    }

    public record HybridKeyPair(KeyPair classicalKp, KeyPair pqKp) {}

    public record HybridPublicKeys(byte[] xpk, byte[] kpk) {}

    public record ServerKexOutput(
            KeyPair xKp_s,
            byte[] ss1,
            byte[] ct,
            byte[] ss2
    ) {}

    /**
     * Generates both ephemeral keypairs for the client (X25519 + ML-KEM-768).
     */
    public HybridKeyPair generateClientKeyPairs() {
        KeyPair xKp = classicalKex.generateKeyPair();
        KeyPair kKp = pqKem.generateKeyPair();
        return new HybridKeyPair(xKp, kKp);
    }

    /**
     * Server-side processing of client key shares:
     * 1. Generates ephemeral server X25519 keypair.
     * 2. Computes ss1 = X25519(xsk_s, xpk_c).
     * 3. Encapsulates ML-KEM against kpk_c -> (ct, ss2).
     */
    public ServerKexOutput serverExchange(byte[] xpk_c, byte[] kpk_c) {
        KeyPair xKp_s = classicalKex.generateKeyPair();
        PublicKey peerXpk = classicalKex.decodePublicKey(xpk_c);
        byte[] ss1 = classicalKex.deriveSharedSecret(xKp_s.getPrivate(), peerXpk);

        PublicKey peerKpk = pqKem.decodePublicKey(kpk_c);
        EncapsulationResult encResult = pqKem.encapsulate(peerKpk);

        return new ServerKexOutput(xKp_s, ss1, encResult.ciphertext(), encResult.sharedSecret());
    }

    /**
     * Client-side processing of server key shares:
     * 1. Computes ss1 = X25519(xsk_c, xpk_s).
     * 2. Decapsulates ct with ksk_c -> ss2.
     */
    public record ClientSecrets(byte[] ss1, byte[] ss2) {}

    public ClientSecrets clientDeriveSecrets(
            PrivateKey xsk_c, byte[] xpk_s,
            PrivateKey ksk_c, byte[] ct) {
        PublicKey serverXpk = classicalKex.decodePublicKey(xpk_s);
        byte[] ss1 = classicalKex.deriveSharedSecret(xsk_c, serverXpk);
        byte[] ss2 = pqKem.decapsulate(ksk_c, ct);
        return new ClientSecrets(ss1, ss2);
    }

    public X25519KeyExchange getClassicalKex() {
        return classicalKex;
    }

    public MlKemKeyExchange getPqKem() {
        return pqKem;
    }
}
