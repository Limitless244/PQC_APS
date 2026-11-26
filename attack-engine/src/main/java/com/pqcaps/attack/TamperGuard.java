package com.pqcaps.attack;

/**
 * Detects ciphertext and handshake message tampering while preventing oracle leaks.
 *
 * <p>Rule:
 * When an authentication tag fails (e.g. GCM tag mismatch or Finished verifyData mismatch),
 * {@code TamperGuard}:
 * <ol>
 *   <li>Emits a high-severity {@code TAMPER} event with forensic details into {@link EventLog}.</li>
 *   <li>Provides a generic, non-oracle exception message to the caller/network ("Record decryption failed"
 *       or "Handshake failed") so attackers cannot learn padding or tag error characteristics.</li>
 * </ol>
 */
public final class TamperGuard {

    private final EventLog eventLog;

    public TamperGuard() {
        this(EventLog.getInstance());
    }

    public TamperGuard(EventLog eventLog) {
        this.eventLog = eventLog;
    }

    /**
     * Intercepts an AEAD authentication tag failure on a record.
     */
    public SecurityException handleAeadTampering(Exception cause, long seq, byte[] nonce, String suite) {
        String nonceHex = hex4(nonce);
        eventLog.record(
                DetectionEvent.AttackType.TAMPER,
                DetectionEvent.Severity.HIGH,
                "TamperGuard",
                suite,
                DetectionEvent.Action.BLOCKED,
                String.format("AEAD authentication tag failure at record seq=%d, nonce=%s... Details: %s",
                        seq, nonceHex, cause.getClass().getSimpleName())
        );
        // Generic error returned to network
        return new SecurityException("Record decryption failed");
    }

    /**
     * Intercepts a Finished message key confirmation failure.
     */
    public SecurityException handleFinishedTampering(String suite, String context) {
        eventLog.record(
                DetectionEvent.AttackType.TAMPER,
                DetectionEvent.Severity.HIGH,
                "TamperGuard",
                suite,
                DetectionEvent.Action.BLOCKED,
                "Finished verifyData verification failed: transcript hash or KEM encapsulation ciphertext was tampered (" + context + ")"
        );
        return new SecurityException("Handshake failed");
    }

    private static String hex4(byte[] b) {
        return (b == null || b.length < 4) ? "null"
                : String.format("%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    }
}
