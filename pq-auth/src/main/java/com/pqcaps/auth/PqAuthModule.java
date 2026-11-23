package com.pqcaps.auth;

/**
 * Placeholder for the post-quantum authentication module.
 *
 * <p>Phase 1 adds: ClassicalSigner (ECDSA / RSA-2048 signatures).
 * Phase 3 adds: MlDsaSigner (ML-DSA-65 / FIPS 204 signatures over the full
 * handshake transcript, preventing MITM and downgrade attacks).
 *
 * <p><b>Why sign the transcript?</b> Without a signature binding every field
 * of the handshake (public keys, nonces, ciphertext, suite list), an active
 * man-in-the-middle can substitute their own keys undetected.
 */
public final class PqAuthModule {

    private PqAuthModule() { /* utility class */ }

    public static void main(String[] args) {
        System.out.println("pq-auth module stub — Phase 1/3 will implement signatures.");
    }
}
