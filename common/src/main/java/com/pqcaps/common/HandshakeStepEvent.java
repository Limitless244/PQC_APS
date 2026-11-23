package com.pqcaps.common;

import java.time.Instant;

/**
 * Immutable value object representing an observed handshake event.
 */
public record HandshakeStepEvent(
        String stepName,
        String direction,
        int messageBytes,
        String hex4,
        String outcome,
        Instant timestamp
) {}
