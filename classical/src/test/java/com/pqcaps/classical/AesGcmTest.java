package com.pqcaps.classical;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * AES-256-GCM correctness and security property tests.
 *
 * <p>Tests:
 * <ol>
 *   <li>Round-trip: encrypt then decrypt returns the original plaintext.</li>
 *   <li>Tamper test: a single flipped bit in the ciphertext fails authentication.</li>
 *   <li>Wrong key: decryption with a different key fails.</li>
 *   <li>Wrong nonce: decryption with a wrong nonce fails.</li>
 *   <li>Wrong AAD: decryption with different AAD fails (AAD is authenticated).</li>
 * </ol>
 */
class AesGcmTest {

    private static final AesGcmCipher CIPHER = new AesGcmCipher();

    /** A fixed 32-byte test key (all zeros — never use in production). */
    private static final byte[] KEY   = new byte[32];
    /** A fixed 12-byte test nonce. */
    private static final byte[] NONCE = new byte[12];
    /** Test AAD. */
    private static final byte[] AAD   = "pqcaps-test-aad".getBytes();

    // ── Round-trip ────────────────────────────────────────────────────────────

    /**
     * Trace:
     * <pre>
     * key       = 00000000...00  (32 bytes)
     * nonce     = 000000...00    (12 bytes)
     * plaintext = "Hello, PQC-APS!"
     * encrypt   → ct (15 + 16 tag = 31 bytes)
     * decrypt   → "Hello, PQC-APS!"  ✓
     * </pre>
     */
    @Test
    void roundTrip_plaintextSurvivesEncryptDecrypt() {
        byte[] plaintext = "Hello, PQC-APS!".getBytes();
        byte[] ciphertext = CIPHER.encrypt(KEY, NONCE, AAD, plaintext);

        // ciphertext must be longer than plaintext by exactly the 16-byte GCM tag
        assertThat(ciphertext.length).isEqualTo(plaintext.length + 16);

        byte[] recovered = CIPHER.decrypt(KEY, NONCE, AAD, ciphertext);
        assertThat(recovered).isEqualTo(plaintext);
    }

    @Test
    void roundTrip_emptyPlaintext_works() {
        byte[] ct = CIPHER.encrypt(KEY, NONCE, AAD, new byte[0]);
        assertThat(ct.length).isEqualTo(16); // just the tag
        assertThat(CIPHER.decrypt(KEY, NONCE, AAD, ct)).isEmpty();
    }

    // ── Tamper tests ──────────────────────────────────────────────────────────

    /**
     * Flipping ONE bit in the ciphertext body must fail GCM tag verification.
     *
     * <p>This demonstrates that AES-GCM is an AEAD scheme:
     * any modification to the ciphertext is detected before the plaintext is returned.
     */
    @Test
    void tamper_flippedBitInCiphertext_throwsSecurityException() {
        byte[] plaintext  = "Sensitive data".getBytes();
        byte[] ciphertext = CIPHER.encrypt(KEY, NONCE, AAD, plaintext);

        // Flip bit 0 of byte 0 in the ciphertext body
        byte[] tampered = Arrays.copyOf(ciphertext, ciphertext.length);
        tampered[0] ^= 0x01;

        assertThatThrownBy(() -> CIPHER.decrypt(KEY, NONCE, AAD, tampered))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Decryption failed");
    }

    @Test
    void tamper_flippedBitInTag_throwsSecurityException() {
        byte[] ciphertext = CIPHER.encrypt(KEY, NONCE, AAD, "data".getBytes());

        // Flip a bit in the last byte (the GCM tag area)
        byte[] tampered = Arrays.copyOf(ciphertext, ciphertext.length);
        tampered[tampered.length - 1] ^= 0x80;

        assertThatThrownBy(() -> CIPHER.decrypt(KEY, NONCE, AAD, tampered))
                .isInstanceOf(SecurityException.class);
    }

    // ── Wrong-key / wrong-nonce tests ─────────────────────────────────────────

    @Test
    void wrongKey_decryptionFails() {
        byte[] ct      = CIPHER.encrypt(KEY, NONCE, AAD, "secret".getBytes());
        byte[] wrongKey = new byte[32];
        wrongKey[0] = 1; // differ in one byte

        assertThatThrownBy(() -> CIPHER.decrypt(wrongKey, NONCE, AAD, ct))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void wrongNonce_decryptionFails() {
        byte[] ct         = CIPHER.encrypt(KEY, NONCE, AAD, "secret".getBytes());
        byte[] wrongNonce = new byte[12];
        wrongNonce[0] = 1;

        assertThatThrownBy(() -> CIPHER.decrypt(KEY, wrongNonce, AAD, ct))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void wrongAad_decryptionFails() {
        byte[] ct      = CIPHER.encrypt(KEY, NONCE, AAD, "secret".getBytes());
        byte[] wrongAad = "different-aad".getBytes();

        assertThatThrownBy(() -> CIPHER.decrypt(KEY, NONCE, wrongAad, ct))
                .isInstanceOf(SecurityException.class);
    }
}
