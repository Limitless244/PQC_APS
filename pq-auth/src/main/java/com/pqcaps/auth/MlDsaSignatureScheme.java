package com.pqcaps.auth;

import com.pqcaps.common.SignatureScheme;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * Post-Quantum Digital Signature Scheme implementing {@link SignatureScheme}
 * using ML-DSA-65 (NIST FIPS 204 / Dilithium3).
 *
 * <p>Properties:
 * <ul>
 *   <li>Security Level: NIST Category 3 (128-bit quantum security, equivalent to AES-192)</li>
 *   <li>Signature size: ~3309 bytes</li>
 *   <li>Public key size: 1952 bytes (raw) / ~1976 bytes (X.509 DER SubjectPublicKeyInfo)</li>
 *   <li>Hardness: Module Learning with Errors (M-LWE) and Module Short Integer Solution (M-SIS)</li>
 * </ul>
 *
 * <p>Used in Phase 3 for authenticating the handshake transcript, preventing MITM
 * and downgrade attacks even against quantum adversaries equipped with Shor's algorithm.
 */
public final class MlDsaSignatureScheme implements SignatureScheme {

    public static final String ALGORITHM = "ML-DSA-65";
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
            throw new IllegalStateException("Failed to generate ML-DSA-65 keypair", e);
        }
    }

    @Override
    public byte[] sign(PrivateKey sk, byte[] data) {
        if (sk == null || data == null) {
            throw new IllegalArgumentException("Private key and data cannot be null");
        }
        try {
            Signature sig = Signature.getInstance(ALGORITHM, PROVIDER);
            sig.initSign(sk);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign data with ML-DSA-65", e);
        }
    }

    @Override
    public boolean verify(PublicKey pk, byte[] data, byte[] signature) {
        if (pk == null || data == null || signature == null) {
            return false;
        }
        try {
            Signature sig = Signature.getInstance(ALGORITHM, PROVIDER);
            sig.initVerify(pk);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
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
            throw new IllegalArgumentException("Failed to decode ML-DSA-65 public key", e);
        }
    }

    // ── Pinned Key File Management ─────────────────────────────────────────────

    /**
     * Saves a pinned server public key to disk in binary DER format.
     *
     * @param pk   ML-DSA-65 public key
     * @param path target file path
     * @throws IOException on I/O error
     */
    public static void savePinnedPublicKey(PublicKey pk, Path path) throws IOException {
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }
        Files.write(path, pk.getEncoded());
    }

    /**
     * Loads a pinned server public key from disk in binary DER format.
     *
     * @param path source file path
     * @return decoded ML-DSA-65 PublicKey
     * @throws IOException on I/O error
     */
    public static PublicKey loadPinnedPublicKey(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        return new MlDsaSignatureScheme().decodePublicKey(bytes);
    }
}
