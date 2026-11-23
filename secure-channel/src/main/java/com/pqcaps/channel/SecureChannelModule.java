package com.pqcaps.channel;

/**
 * Placeholder for the secure-channel module.
 *
 * <p>Phase 1 adds: AesGcmChannel (AES-256-GCM record layer, vulnerable nonce mgr).
 * Phase 3 adds: HybridHandshake (complete 10-step handshake spec).
 * Phase 4 adds: CounterNonceManager, sequence numbers, rekeying.
 *
 * <p><b>AES-256-GCM design note</b>: GCM requires a 96-bit nonce. Reusing any
 * nonce with the same key is catastrophic — it destroys both confidentiality
 * and authenticity. This module enforces a strict monotonic counter nonce
 * and forces a rekeying before the counter would overflow.
 */
public final class SecureChannelModule {

    private SecureChannelModule() { /* utility class */ }

    public static void main(String[] args) {
        System.out.println("secure-channel module stub — Phase 1/3 will implement the channel.");
    }
}
