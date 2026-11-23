package com.pqcaps.kex;

/**
 * Placeholder for the hybrid key-exchange module.
 *
 * <p>Phase 1 adds: ClassicalKeyExchange (X25519 / ECDH).
 * Phase 3 adds: HybridKeyExchange (X25519 + ML-KEM-768) + HkdfUtil.
 *
 * <p><b>Why hybrid?</b> A classical attacker breaking X25519 alone would
 * compromise the session. A quantum attacker breaking ML-KEM-768 alone would
 * also compromise it. Combining both means an attacker needs to break BOTH —
 * providing security against classical <em>and</em> quantum threats simultaneously.
 */
public final class HybridKexModule {

    private HybridKexModule() { /* utility class */ }

    public static void main(String[] args) {
        System.out.println("hybrid-kex module stub — Phase 1/3 will implement key exchange.");
    }
}
