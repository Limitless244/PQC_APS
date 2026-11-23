package com.pqcaps.kex;

import com.pqcaps.classical.HkdfSha256;
import com.pqcaps.common.SessionKeys;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Key schedule and key confirmation for the Hybrid (and Post-Quantum) secure channel.
 *
 * <p>Key Derivation:
 * <pre>
 * ikm  = ss1 || ss2       (for HYBRID)
 *        ss2              (for PQ_ONLY)
 *        ss1              (for CLASSICAL fallback)
 * salt = nonce_c || nonce_s
 * info = "pqcaps/v1/" + suiteId + SHA-256(transcript)
 * PRK  = HMAC-SHA256(salt, ikm)
 * OKM  = HKDF-Expand(PRK, info, 96 bytes)
 *   -> clientToServer : OKM[0..31]   (AES-256 key)
 *   -> serverToClient : OKM[32..63]  (AES-256 key)
 *   -> finishedKey    : OKM[64..95]  (HMAC key confirmation key)
 * </pre>
 *
 * <p>Key Confirmation:
 * <pre>
 * Finished = HMAC-SHA256(finishedKey, transcript_hash)
 * </pre>
 */
public final class HybridKeySchedule {

    private static final String HMAC_ALG = "HmacSHA256";

    private HybridKeySchedule() {}

    /**
     * Derives session keys for client-to-server, server-to-client, and Finished verification.
     *
     * @param suiteId        negotiated suite identifier (e.g. "HYBRID" or "PQ_ONLY")
     * @param ss1            classical shared secret (X25519), null or empty for PQ_ONLY
     * @param ss2            post-quantum shared secret (ML-KEM-768), null or empty for CLASSICAL
     * @param nonce_c        32-byte client nonce
     * @param nonce_s        32-byte server nonce
     * @param transcriptHash 32-byte SHA-256 hash of the complete handshake transcript
     * @return derived {@link SessionKeys} containing c2s, s2c, and finishedKey
     */
    public static SessionKeys deriveSessionKeys(
            String suiteId,
            byte[] ss1,
            byte[] ss2,
            byte[] nonce_c,
            byte[] nonce_s,
            byte[] transcriptHash) {

        if (nonce_c == null || nonce_s == null || transcriptHash == null) {
            throw new IllegalArgumentException("Nonces and transcript hash cannot be null");
        }

        // 1. IKM composition: ss1 || ss2 for HYBRID, ss2 for PQ_ONLY, ss1 for CLASSICAL
        byte[] ikm;
        if (ss1 != null && ss1.length > 0 && ss2 != null && ss2.length > 0) {
            ikm = concat(ss1, ss2);
        } else if (ss2 != null && ss2.length > 0) {
            ikm = ss2.clone();
        } else if (ss1 != null && ss1.length > 0) {
            ikm = ss1.clone();
        } else {
            throw new IllegalArgumentException("At least one shared secret (ss1 or ss2) is required");
        }

        // 2. Salt: nonce_c || nonce_s
        byte[] salt = concat(nonce_c, nonce_s);

        // 3. Info: "pqcaps/v1/" + suiteId + SHA-256(transcript)
        byte[] suitePrefix = ("pqcaps/v1/" + suiteId).getBytes(StandardCharsets.UTF_8);
        byte[] info = concat(suitePrefix, transcriptHash);

        // 4. HKDF Extract & Expand (96 bytes = 3 x 32-byte keys)
        byte[] prk = HkdfSha256.extract(salt, ikm);
        byte[] okm = HkdfSha256.expand(prk, info, 96);

        byte[] c2s = Arrays.copyOfRange(okm, 0, 32);
        byte[] s2c = Arrays.copyOfRange(okm, 32, 64);
        byte[] finishedKey = Arrays.copyOfRange(okm, 64, 96);

        // Zeroize intermediate secrets
        Arrays.fill(ikm, (byte) 0);
        Arrays.fill(prk, (byte) 0);
        Arrays.fill(okm, (byte) 0);

        return new SessionKeys(c2s, s2c, finishedKey);
    }

    /**
     * Computes the Finished key confirmation verifyData:
     * {@code HMAC-SHA256(finishedKey, transcriptHash)}.
     *
     * @param finishedKey    32-byte finished key from session keys
     * @param transcriptHash 32-byte SHA-256 hash of the handshake transcript
     * @return 32-byte HMAC authentication tag
     */
    public static byte[] computeFinished(byte[] finishedKey, byte[] transcriptHash) {
        if (finishedKey == null || transcriptHash == null) {
            throw new IllegalArgumentException("Finished key and transcript hash cannot be null");
        }
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(finishedKey, HMAC_ALG));
            return mac.doFinal(transcriptHash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to compute HMAC Finished tag", e);
        }
    }

    /**
     * Verifies the peer's Finished verifyData in constant time.
     *
     * @param finishedKey        32-byte finished key from session keys
     * @param transcriptHash     32-byte SHA-256 hash of the handshake transcript
     * @param receivedVerifyData verifyData received from peer
     * @return {@code true} if valid; {@code false} if invalid or tampered
     */
    public static boolean verifyFinished(byte[] finishedKey, byte[] transcriptHash, byte[] receivedVerifyData) {
        if (receivedVerifyData == null) {
            return false;
        }
        byte[] expected = computeFinished(finishedKey, transcriptHash);
        return MessageDigest.isEqual(expected, receivedVerifyData);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
