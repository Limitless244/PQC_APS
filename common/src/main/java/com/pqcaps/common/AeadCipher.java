package com.pqcaps.common;

/**
 * Contract for an Authenticated Encryption with Associated Data (AEAD) cipher.
 *
 * <p>Phase 1 implementation: {@code AesGcmCipher} (AES-256-GCM, 128-bit tag).
 *
 * <p><b>Nonce discipline</b>: GCM nonces MUST be unique per (key, nonce) pair.
 * Reusing a nonce with the same key destroys both confidentiality and authenticity.
 * Callers are responsible for supplying a fresh nonce on every call; the
 * {@code ClassicalSecureChannel} enforces this via a counter.
 *
 * <p><b>AAD</b>: Associated data is authenticated but not encrypted.
 * Include context (e.g., the record sequence number) so an attacker cannot
 * reorder or replay records while keeping a valid tag.
 */
public interface AeadCipher {

    /**
     * Encrypts and authenticates {@code plaintext}.
     *
     * @param key       32-byte AES-256 key
     * @param nonce     12-byte GCM nonce (must be unique per key)
     * @param aad       associated data authenticated but not encrypted; may be empty
     * @param plaintext message to encrypt
     * @return ciphertext with the 16-byte GCM authentication tag appended
     */
    byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext);

    /**
     * Decrypts and verifies {@code ciphertext}.
     *
     * @param key        32-byte AES-256 key
     * @param nonce      12-byte GCM nonce (must match the value used at encrypt time)
     * @param aad        same associated data passed at encrypt time
     * @param ciphertext ciphertext with tag appended (output of {@link #encrypt})
     * @return the original plaintext
     * @throws IllegalStateException if the GCM tag is invalid (tampered data)
     */
    byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext);
}
