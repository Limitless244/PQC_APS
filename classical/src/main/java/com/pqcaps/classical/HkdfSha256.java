package com.pqcaps.classical;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * HKDF-SHA256 key derivation function, per <a href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869</a>.
 *
 * <p>HKDF turns a high-entropy but potentially non-uniform secret (like a raw ECDH
 * output) into uniformly random key material of any desired length. It operates in
 * two steps:
 * <ol>
 *   <li><b>Extract</b>: {@code PRK = HMAC-SHA256(salt, IKM)} — "concentrates" the entropy.</li>
 *   <li><b>Expand</b>: {@code OKM = T(1)||T(2)||…} — stretches PRK to the desired length.</li>
 * </ol>
 *
 * <p>Example trace (abbreviated from RFC 5869 Test Case 1):
 * <pre>
 * IKM   = 0x0b0b0b...0b  (22 bytes)
 * salt  = 0x000102...0c  (13 bytes)
 * info  = 0xf0f1...f9    (10 bytes)
 * L     = 42
 * PRK   = 077709362c...  (32 bytes)
 * OKM   = 3cb25f25fa...  (42 bytes)
 * </pre>
 */
public final class HkdfSha256 {

    private static final String HMAC_ALG = "HmacSHA256";
    /** SHA-256 output length in bytes. */
    public static final int HASH_LEN = 32;

    private HkdfSha256() { /* static utility — not instantiable */ }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * HKDF Extract step: {@code PRK = HMAC-SHA256(salt, IKM)}.
     *
     * <p>If {@code salt} is null or empty, RFC 5869 §2.2 says to use a string of
     * HashLen zero bytes.
     *
     * @param salt optional salt (e.g., the concatenated client+server nonces)
     * @param ikm  input key material (e.g., raw ECDH shared secret)
     * @return 32-byte pseudorandom key (PRK)
     */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        return hmacSha256(actualSalt, ikm);
    }

    /**
     * HKDF Expand step: stretches {@code prk} to exactly {@code length} bytes.
     *
     * <p>Internally computes a chain {@code T(i) = HMAC(PRK, T(i-1) || info || i)},
     * where i is a single byte counter 0x01..0xFF, limiting output to 255 × 32 = 8160 bytes.
     *
     * @param prk    32-byte PRK from {@link #extract}
     * @param info   context string (e.g., {@code "pqcaps-classical-c2s".getBytes()})
     * @param length desired output length in bytes (1 ≤ length ≤ 8160)
     * @return {@code length} bytes of uniform key material
     */
    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length <= 0 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException(
                    "HKDF expand: length must be 1.." + (255 * HASH_LEN) + ", got " + length);
        }
        int n = (int) Math.ceil((double) length / HASH_LEN);
        byte[] okm   = new byte[n * HASH_LEN];
        byte[] t     = new byte[0]; // T(0) = empty string per RFC 5869

        for (int i = 1; i <= n; i++) {
            // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
            byte[] input = concat(t, info, new byte[]{(byte) i});
            t = hmacSha256(prk, input);
            System.arraycopy(t, 0, okm, (i - 1) * HASH_LEN, HASH_LEN);
        }
        return Arrays.copyOf(okm, length);
    }

    /**
     * Convenience: extract + expand in one call.
     *
     * <p>Example for a 32-byte AES key:
     * <pre>{@code
     * byte[] key = HkdfSha256.deriveKey(
     *     sharedSecret,
     *     nonce_c_concat_nonce_s,
     *     "pqcaps-classical-c2s".getBytes(UTF_8),
     *     32);
     * }</pre>
     *
     * @param ikm    raw input key material (e.g., ECDH shared secret)
     * @param salt   salt bytes (e.g., nonce_c || nonce_s)
     * @param info   context info bytes (labels each derived key)
     * @param length desired output length in bytes
     * @return derived key of {@code length} bytes
     */
    public static byte[] deriveKey(byte[] ikm, byte[] salt, byte[] info, int length) {
        byte[] prk = extract(salt, ikm);
        return expand(prk, info, length);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(key, HMAC_ALG));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** Concatenates arrays without allocating intermediate strings. */
    static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }
}
