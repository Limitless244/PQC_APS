package com.pqcaps.attack;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.Instant;
import java.util.UUID;

/**
 * Structured security event emitted when an attack or policy violation is detected.
 *
 * <p>Persisted to {@code detection-events.jsonl} for consumption by the Phase 6
 * monitoring and benchmark dashboard.
 *
 * @param id         unique event UUID
 * @param timestamp  time of detection (UTC)
 * @param attackType categorized attack classification
 * @param severity   threat severity level
 * @param component  internal module or guard that raised the event
 * @param suite      cipher suite in use (e.g. "HYBRID", "CLASSICAL", "PQ_ONLY")
 * @param action     mitigation taken: BLOCKED or LOGGED
 * @param detail     human-readable forensic summary (strictly zero raw secrets)
 */
public record DetectionEvent(
        String id,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        Instant timestamp,
        AttackType attackType,
        Severity severity,
        String component,
        String suite,
        Action action,
        String detail
) {

    public enum AttackType {
        DOWNGRADE,
        MITM,
        REPLAY,
        NONCE_REUSE,
        TAMPER,
        KEY_REUSE,
        WEAK_RANDOMNESS,
        TIMING
    }

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH
    }

    public enum Action {
        BLOCKED,
        LOGGED
    }

    /**
     * Factory creating a new DetectionEvent with a fresh UUID and current UTC timestamp.
     */
    public static DetectionEvent create(
            AttackType attackType,
            Severity severity,
            String component,
            String suite,
            Action action,
            String detail) {
        return new DetectionEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                attackType,
                severity,
                component,
                suite != null ? suite : "UNKNOWN",
                action,
                detail
        );
    }
}
