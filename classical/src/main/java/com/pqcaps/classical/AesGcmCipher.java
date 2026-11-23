package com.pqcaps.classical;

import com.pqcaps.common.AeadCipher;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM authenticated encryption.
 *
 * <p>GCM (Galois/Counter Mode) combines AES-CTR encryption with a GHASH
 * authentication tag. The 128-bit tag covers both the ciphertext and the
 * Additional Authenticated Data (AAD), making any tampering detectable.
 *
 * <p><b>Critical GCM property</b>: the (key, nonce) pair MUST be unique for every
 * encryption. Reusing a nonce with the same key reveals the XOR of plaintexts AND
 * lets an attacker recover the GHASH subkey, which allows forging arbitrary tags.
 * See {@code HandshakeConfig.unsafeNonceMode} for the intentional Phase 1 weakness.
 *
 * <p><b>Trace</b> (AES-256-GCM encrypt):
 * <pre>
 * key       = 32 bytes (from HKDF)
 * nonce     = 12 bytes (from counter)
 * aad       = "pqcaps-classical-record" || seq (8 bytes big-endian)
 * plaintext = "hello" (5 bytes)
 * ──────────────────────────────────────────────
 * ciphertext = encrypted bytes (5 bytes) + GCM tag (16 bytes) = 21 bytes
 * </pre>
 */
public final class AesGcmCipher implements AeadCipher {

    private static final String CIPHER_ALG = "AES/GCM/NoPadding";
    private static final int    TAG_BITS   = 128; // GCM authentication tag size

    @Override
    public byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALG);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encrypt failed", e);
        }
    }

    /**
     * Decrypts and verifies the GCM tag.
     *
     * <p>If the tag is invalid (tampered ciphertext, wrong key, or wrong nonce),
     * the JDK throws {@link AEADBadTagException}. We wrap this in a clear
     * {@link IllegalStateException} with a generic message — never expose oracle
     * information about <em>why</em> decryption failed (e.g., "padding error" vs
     * "tag mismatch").
     */
    @Override
    public byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALG);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            // IMPORTANT: do NOT reveal which check failed; return a uniform error.
            // "Decryption failed" is the only safe message — no oracle information.
            throw new SecurityException("Decryption failed: authentication tag invalid", e);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decrypt failed", e);
        }
    }
}
