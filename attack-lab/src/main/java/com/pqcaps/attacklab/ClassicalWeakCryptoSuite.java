package com.pqcaps.attacklab;

import com.pqcaps.classical.AesGcmCipher;
import com.pqcaps.classical.X25519KeyExchange;
import com.pqcaps.common.AeadCipher;
import com.pqcaps.common.CryptoSuite;
import com.pqcaps.common.KeyExchange;
import com.pqcaps.common.SignatureScheme;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * Intentionally weak classical suite used only in the attack lab to demonstrate
 * downgrade attacks (VULN-1).
 *
 * <p>Features:
 * <ul>
 *   <li>Suite ID: {@code "CLASSICAL_WEAK"}</li>
 *   <li>Signature: RSA-1024 with SHA-1 (grossly insecure, easily forgeable / factorable)</li>
 *   <li>KEX: X25519</li>
 *   <li>Cipher: AES-GCM</li>
 * </ul>
 */
public final class ClassicalWeakCryptoSuite implements CryptoSuite {

    private static final ClassicalWeakCryptoSuite INSTANCE = new ClassicalWeakCryptoSuite();

    private final X25519KeyExchange kex = new X25519KeyExchange();
    private final WeakRsaSigner signer = new WeakRsaSigner();
    private final AesGcmCipher cipher = new AesGcmCipher();

    private ClassicalWeakCryptoSuite() {}

    public static ClassicalWeakCryptoSuite getInstance() {
        return INSTANCE;
    }

    @Override public String id() { return "CLASSICAL_WEAK"; }
    @Override public KeyExchange keyExchange() { return kex; }
    @Override public SignatureScheme signatureScheme() { return signer; }
    @Override public AeadCipher aeadCipher() { return cipher; }

    /**
     * Weak 1024-bit RSA signer with SHA1withRSA for demo downgrade targets.
     */
    public static final class WeakRsaSigner implements SignatureScheme {
        private static final String ALG = "SHA1withRSA";
        private static final int BITS = 1024;

        @Override
        public KeyPair generateKeyPair() {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(BITS, new SecureRandom());
                return kpg.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException("Weak RSA keygen failed", e);
            }
        }

        @Override
        public byte[] sign(PrivateKey sk, byte[] data) {
            try {
                Signature sig = Signature.getInstance(ALG);
                sig.initSign(sk, new SecureRandom());
                sig.update(data);
                return sig.sign();
            } catch (Exception e) {
                throw new IllegalStateException("Weak RSA sign failed", e);
            }
        }

        @Override
        public boolean verify(PublicKey pk, byte[] data, byte[] signature) {
            try {
                Signature sig = Signature.getInstance(ALG);
                sig.initVerify(pk);
                sig.update(data);
                return sig.verify(signature);
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public PublicKey decodePublicKey(byte[] encoded) {
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(new X509EncodedKeySpec(encoded));
            } catch (Exception e) {
                throw new IllegalArgumentException("Cannot decode weak RSA key", e);
            }
        }
    }
}
