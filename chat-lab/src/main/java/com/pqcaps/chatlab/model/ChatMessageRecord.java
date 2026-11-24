package com.pqcaps.chatlab.model;

import java.time.Instant;

/**
 * Message record representing a sent or received chat message.
 */
public record ChatMessageRecord(
        String id,
        String sender,
        String text,
        long sequenceNumber,
        String status,
        String guardFired,
        String hex4Ciphertext,
        Instant timestamp
) {}
