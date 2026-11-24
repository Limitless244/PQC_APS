package com.pqcaps.chatlab.model;

import java.time.Instant;

/**
 * Outcome of an attacker action recorded on the proxy side.
 * Reports strictly "forwarded / what we saw", never leaking server defense state.
 */
public record AttackerActionOutcome(
        String action,
        String status,
        String detail,
        Instant timestamp
) {}
