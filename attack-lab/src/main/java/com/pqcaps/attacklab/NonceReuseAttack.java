package com.pqcaps.attacklab;

import com.pqcaps.classical.AesGcmCipher;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * ATTACK 4: AES-GCM Nonce Reuse Attack (exploits VULN-3).
 *
 * <p><b>The Weakness</b>: In Phase 1, the nonce counter restarts from 0 or operates
 * under {@code HandshakeConfig.unsafeNonceMode = true}. If the same key is used across
 * channel instances, nonces repeat.
 *
 * <p><b>The Attack (Keystream XOR Leak)</b>:
 * AES-GCM uses Counter (CTR) mode for encryption:
 * <pre>
 *   C1 = P1 ⊕ Keystream(K, Nonce)
 *   C2 = P2 ⊕ Keystream(K, Nonce)
 * </pre>
 * Because the key and nonce are identical, the keystream is identical.
 * XORing the two ciphertexts cancels out the keystream completely:
 * <pre>
 *   C1 ⊕ C2 = (P1 ⊕ KS) ⊕ (P2 ⊕ KS) = P1 ⊕ P2
 * </pre>
 * If the attacker knows or can guess {@code P1} (e.g. a standard command header, known format),
 * they recover the secret plaintext {@code P2} with zero key knowledge:
 * <pre>
 *   P2 = (C1 ⊕ C2) ⊕ P1
 * </pre>
 */
public final class NonceReuseAttack {

    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("  ATTACK 4: AES-GCM Nonce Reuse Keystream Leak (exploiting VULN-3)");
        System.out.println("======================================================================");

        AttackResult result = execute();
        System.out.println();
        System.out.println("Attack Success : " + result.success());
        System.out.println("Vulnerability  : " + result.vulnerabilityId());
        System.out.println("Evidence       : " + result.evidence());
    }

    /**
     * Executes the GCM nonce reuse keystream cancellation attack.
     *
     * @return the AttackResult demonstrating successful plaintext recovery.
     */
    public static AttackResult execute() {
        AesGcmCipher cipher = new AesGcmCipher();

        // 1. Session key and reused nonce
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);

        long sequence = 0L;
        byte[] reusedNonce = ClassicalSecureChannel.buildNonce(sequence);
        byte[] aad = ClassicalSecureChannel.buildAad(sequence);

        // 2. Two messages: P1 is known to the attacker, P2 is confidential
        String p1Str = "TRANSFER $100 TO ALICE [TXN-001]";
        String p2Str = "TRANSFER $950 TO EVE   [TXN-002]";

        byte[] p1 = p1Str.getBytes(StandardCharsets.UTF_8);
        byte[] p2 = p2Str.getBytes(StandardCharsets.UTF_8);

        System.out.printf("[STEP 1] Session Key: %s...  Reused Nonce: %s...%n",
                ClassicalHandshake.hex4(key), ClassicalHandshake.hex4(reusedNonce));
        System.out.printf("[STEP 2] P1 (Known)   : \"%s\"%n", p1Str);
        System.out.printf("[STEP 2] P2 (Target)  : \"%s\"%n", p2Str);

        // 3. Encrypt both under the SAME (key, nonce) pair (VULN-3)
        byte[] c1 = cipher.encrypt(key, reusedNonce, aad, p1);
        byte[] c2 = cipher.encrypt(key, reusedNonce, aad, p2);

        System.out.printf("[STEP 3] C1 ciphertext: %s... (len=%d, includes 16-byte tag)%n",
                ClassicalHandshake.hex4(c1), c1.length);
        System.out.printf("[STEP 3] C2 ciphertext: %s... (len=%d, includes 16-byte tag)%n",
                ClassicalHandshake.hex4(c2), c2.length);

        // 4. Compute C1 ^ C2 over the ciphertext bodies (excluding 16-byte GCM tags)
        int bodyLen = p1.length;
        byte[] c1XorC2 = new byte[bodyLen];
        for (int i = 0; i < bodyLen; i++) {
            c1XorC2[i] = (byte) (c1[i] ^ c2[i]);
        }

        byte[] p1XorP2 = new byte[bodyLen];
        for (int i = 0; i < bodyLen; i++) {
            p1XorP2[i] = (byte) (p1[i] ^ p2[i]);
        }

        boolean keystreamCancelled = Arrays.equals(c1XorC2, p1XorP2);
        System.out.printf("[STEP 4] Keystream cancelled: C1 ^ C2 == P1 ^ P2 ? %b%n", keystreamCancelled);

        // 5. Recover P2: P2 = (C1 ^ C2) ^ P1
        byte[] recoveredP2Bytes = new byte[bodyLen];
        for (int i = 0; i < bodyLen; i++) {
            recoveredP2Bytes[i] = (byte) (c1XorC2[i] ^ p1[i]);
        }
        String recoveredP2Str = new String(recoveredP2Bytes, StandardCharsets.UTF_8);

        System.out.printf("[STEP 5] Recovered P2 : \"%s\"%n", recoveredP2Str);
        boolean success = keystreamCancelled && p2Str.equals(recoveredP2Str);

        String evidence = String.format(
                "GCM Nonce reuse confirmed: Reused nonce %s... under key %s... | C1^C2 == P1^P2 -> Recovered plaintext \"%s\"",
                ClassicalHandshake.hex4(reusedNonce), ClassicalHandshake.hex4(key), recoveredP2Str);

        return new AttackResult(
                "GCM Nonce Reuse Attack",
                success,
                evidence,
                "VULN-3"
        );
    }
}
