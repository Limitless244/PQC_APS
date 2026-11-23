package com.pqcaps.classical;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * HKDF-SHA256 correctness tests against the official RFC 5869 test vectors.
 *
 * <p>These are the most important correctness tests: if HKDF is wrong, all
 * derived keys will be wrong and nothing else can be trusted.
 *
 * <p>Test vectors from: <a href="https://www.rfc-editor.org/rfc/rfc5869#appendix-A">
 * RFC 5869 Appendix A</a>
 */
class HkdfTest {

    // ── Helper ────────────────────────────────────────────────────────────────

    private static byte[] hex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return out;
    }

    // ── Test Case 1 (Basic) ───────────────────────────────────────────────────

    /**
     * RFC 5869 Test Case 1 — with salt and info.
     *
     * <p>Trace:
     * <pre>
     * Hash  = SHA-256
     * IKM   = 0b0b0b0b...0b  (22 bytes of 0x0b)
     * salt  = 000102...0c    (13 bytes)
     * info  = f0f1f2...f9    (10 bytes)
     * L     = 42
     *
     * Extract step:
     *   HMAC-SHA256(key=salt, data=IKM)
     *   PRK = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
     *
     * Expand step (N=2 blocks of 32 bytes, truncated to 42):
     *   T(1) = HMAC(PRK, ""  || info || 0x01) = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
     *   T(2) = HMAC(PRK, T1  || info || 0x02) = ...34007208d5b887185865...
     *   OKM  = T(1)[0..31] || T(2)[0..9]  = 42 bytes below
     * </pre>
     */
    @Test
    void testCase1_withSaltAndInfo() {
        byte[] ikm  = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        int    L    = 42;

        byte[] expectedPrk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expectedOkm = hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        // Extract
        byte[] prk = HkdfSha256.extract(salt, ikm);
        assertThat(prk).as("PRK (Test Case 1)").isEqualTo(expectedPrk);

        // Expand
        byte[] okm = HkdfSha256.expand(prk, info, L);
        assertThat(okm).as("OKM (Test Case 1)").isEqualTo(expectedOkm);

        // Combined convenience method
        byte[] okmDirect = HkdfSha256.deriveKey(ikm, salt, info, L);
        assertThat(okmDirect).as("deriveKey == expand(extract()) (Test Case 1)").isEqualTo(expectedOkm);
    }

    // ── Test Case 2 (Longer inputs) ───────────────────────────────────────────

    @Test
    void testCase2_longerInputs() {
        byte[] ikm  = hex("000102030405060708090a0b0c0d0e0f"
                        + "101112131415161718191a1b1c1d1e1f"
                        + "202122232425262728292a2b2c2d2e2f"
                        + "303132333435363738393a3b3c3d3e3f"
                        + "404142434445464748494a4b4c4d4e4f");
        byte[] salt = hex("606162636465666768696a6b6c6d6e6f"
                        + "707172737475767778797a7b7c7d7e7f"
                        + "808182838485868788898a8b8c8d8e8f"
                        + "909192939495969798999a9b9c9d9e9f"
                        + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] info = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                        + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                        + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                        + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                        + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        int L = 82;

        byte[] expectedOkm = hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                                + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                                + "cc30c58179ec3e87c14c01d5c1f3434f1d87");

        byte[] okm = HkdfSha256.deriveKey(ikm, salt, info, L);
        assertThat(okm).as("OKM (Test Case 2)").isEqualTo(expectedOkm);
    }

    // ── Test Case 3 (No salt, no info) ───────────────────────────────────────

    @Test
    void testCase3_noSaltNoInfo() {
        byte[] ikm  = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = null; // RFC: use HashLen zero bytes as salt
        byte[] info = new byte[0];
        int    L    = 42;

        byte[] expectedPrk = hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        byte[] expectedOkm = hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

        byte[] prk = HkdfSha256.extract(salt, ikm);
        assertThat(prk).as("PRK (Test Case 3)").isEqualTo(expectedPrk);

        byte[] okm = HkdfSha256.expand(prk, info, L);
        assertThat(okm).as("OKM (Test Case 3)").isEqualTo(expectedOkm);
    }

    // ── Edge-case tests ───────────────────────────────────────────────────────

    @Test
    void expand_invalidLength_throws() {
        byte[] prk  = new byte[32];
        byte[] info = new byte[0];
        assertThatThrownBy(() -> HkdfSha256.expand(prk, info, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("length");
        assertThatThrownBy(() -> HkdfSha256.expand(prk, info, 255 * 32 + 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void differentInfoLabels_produceDifferentKeys() {
        byte[] ikm  = new byte[32]; // all zeros
        byte[] salt = new byte[32];
        byte[] c2s  = HkdfSha256.deriveKey(ikm, salt, "pqcaps-classical-c2s".getBytes(), 32);
        byte[] s2c  = HkdfSha256.deriveKey(ikm, salt, "pqcaps-classical-s2c".getBytes(), 32);
        // The two derived keys MUST be different — same IKM, different info labels
        assertThat(c2s).isNotEqualTo(s2c);
    }
}
