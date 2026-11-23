package com.pqcaps.attack;

import com.pqcaps.common.SignatureScheme;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * Prevents Man-In-The-Middle (MITM) attacks by enforcing strict public-key pinning
 * and cryptographic transcript signature verification.
 *
 * <p>VULN-4 in Phase 1 allowed clients to skip server public-key pinning, enabling
 * a proxy to substitute its own identity key and intercept confidential messages.
 */
public final class MitmGuard {

    private final EventLog eventLog;

    public MitmGuard() {
        this(EventLog.getInstance());
    }

    public MitmGuard(EventLog eventLog) {
        this.eventLog = eventLog;
    }

    /**
     * Validates that a pinned server key is configured (FAIL-CLOSED rule).
     */
    public void validateKeyPinningConfigured(
            PublicKey pinnedKey,
            boolean allowInsecureNoPinning,
            String suite) {
        if (pinnedKey == null) {
            if (!allowInsecureNoPinning) {
                eventLog.record(
                        DetectionEvent.AttackType.MITM,
                        DetectionEvent.Severity.HIGH,
                        "MitmGuard",
                        suite,
                        DetectionEvent.Action.BLOCKED,
                        "FAIL-CLOSED: No pinned server identity key configured. Handshake rejected."
                );
                throw new SecurityException(
                        "FAIL-CLOSED: Pinned server public key is required. Insecure operation is disabled by default.");
            } else {
                eventLog.record(
                        DetectionEvent.AttackType.MITM,
                        DetectionEvent.Severity.MEDIUM,
                        "MitmGuard",
                        suite,
                        DetectionEvent.Action.LOGGED,
                        "WARNING: allowInsecureNoPinning=true: operating without pinned identity anchor!"
                );
            }
        }
    }

    /**
     * Verifies that the server signature over the transcript verifies against the pinned public key.
     */
    public void verifyServerSignature(
            SignatureScheme scheme,
            PublicKey pinnedKey,
            byte[] transcript,
            byte[] signature,
            String suite) {

        if (pinnedKey == null) {
            throw new SecurityException("Cannot verify signature: pinned key is null");
        }

        boolean valid = scheme.verify(pinnedKey, transcript, signature);
        if (!valid) {
            eventLog.record(
                    DetectionEvent.AttackType.MITM,
                    DetectionEvent.Severity.HIGH,
                    "MitmGuard",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    "Server identity signature verification failed! Possible on-path key substitution or transcript tampering."
            );
            throw new SecurityException("MITM attack detected: server identity signature verification failed");
        }
    }
}
