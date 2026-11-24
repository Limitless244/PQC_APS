package com.pqcaps.chatlab.model;

import java.time.Instant;

/**
 * Traffic item captured on the wire by Mallory's TCP proxy.
 * In CLASSICAL-VULNERABLE MITM mode, attackerView contains the genuine decrypted plaintext.
 * In HARDENED and HYBRID modes, attackerView contains only ciphertext hex/sizes.
 */
public record CapturedTrafficRecord(
        String id,
        String direction,
        int length,
        String hex4,
        Long sequenceNumber,
        String attackerView,
        String status,
        Instant timestamp
) {}
