package com.pqcaps.chatlab.model;

import java.time.Instant;

/**
 * Record describing one step in the cryptographic handshake.
 * Never leaks secrets or private keys; shows at most first 4 bytes hex.
 */
public record HandshakeStepRecord(
        String stepName,
        String direction,
        int messageBytes,
        String hex4,
        String outcome,
        Instant timestamp
) {}
