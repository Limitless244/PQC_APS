package com.pqcaps.kex;

import com.pqcaps.common.KemKeyExchange;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import javax.crypto.KeyGenerator;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * Post-Quantum Key Encapsulation Mechanism using ML-KEM-768 (NIST FIPS 203 / Kyber-768).
 *
 * <p>Properties:
 * <ul>
 *   <li>Security Level: NIST Category 3 (equivalent to AES-192, 128-bit quantum security)</li>
 *   <li>Ciphertext size: 1088 bytes</li>
 *   <li>Public key size: 1184 bytes (raw) / ~1208 bytes (X.509 DER SubjectPublicKeyInfo)</li>
 *   <li>Shared secret size: 32 bytes (256 bits)</li>
 *   <li>Hardness: Module Learning with Errors (M-LWE)</li>
 * </ul>
 *
 * <p>IND-CCA2 Security & Implicit Rejection:
 * Under the Fujisaki-Okamoto transform in ML-KEM, an active attacker modifying the ciphertext
 * in transit cannot trigger decapsulation errors or side-channel leakages. Decapsulation of a
 * tampered ciphertext silently produces a pseudorandom secret derived from {@code H(sk || ct)}.
 * Key confirmation via Finished message is therefore essential to detect tampering.
 */
public final class MlKemKeyExchange implements KemKeyExchange {

    public static final String ALGORITHM = "ML-KEM-768";
    public static final String PROVIDER = "BC";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            return kpg.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to generate ML-KEM-768 keypair", e);
        }
    }

    @Override
    public EncapsulationResult encapsulate(PublicKey peerPk) {
        if (peerPk == null) {
            throw new IllegalArgumentException("Peer public key cannot be null");
        }
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
            kg.init(new KEMGenerateSpec(peerPk, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation) kg.generateKey();
            byte[] sharedSecret = secEnc.getEncoded(); // 32 bytes
            byte[] ciphertext = secEnc.getEncapsulation(); // 1088 bytes
            return new EncapsulationResult(ciphertext, sharedSecret);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encapsulate against ML-KEM-768 public key", e);
        }
    }

    @Override
    public byte[] decapsulate(PrivateKey sk, byte[] ciphertext) {
        if (sk == null || ciphertext == null) {
            throw new IllegalArgumentException("Private key and ciphertext cannot be null");
        }
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
            kg.init(new KEMExtractSpec(sk, ciphertext, "AES"));
            SecretKeyWithEncapsulation secDec = (SecretKeyWithEncapsulation) kg.generateKey();
            return secDec.getEncoded(); // 32 bytes
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decapsulate ML-KEM-768 ciphertext", e);
        }
    }

    @Override
    public PublicKey decodePublicKey(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException("Encoded public key cannot be null or empty");
        }
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM, PROVIDER);
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to decode ML-KEM-768 public key", e);
        }
    }
}
