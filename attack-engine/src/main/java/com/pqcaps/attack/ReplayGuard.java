package com.pqcaps.attack;

import java.time.Duration;
import java.time.Instant;
import java.util.BitSet;

/**
 * Prevents message replay attacks (VULN-2) using strict per-direction sequence numbers,
 * sliding-window replay protection, and timestamp validation.
 */
public final class ReplayGuard {

    private static final int DEFAULT_WINDOW_SIZE = 64;
    private final EventLog eventLog;
    private final int windowSize;

    private long expectedNextSeq = 0;
    private long windowMaxSeq = -1;
    private final BitSet receivedWindow = new BitSet();

    public ReplayGuard() {
        this(DEFAULT_WINDOW_SIZE, EventLog.getInstance());
    }

    public ReplayGuard(int windowSize, EventLog eventLog) {
        this.windowSize = windowSize;
        this.eventLog   = eventLog;
    }

    /**
     * Strict sequential mode: records must arrive with seq == expectedNextSeq.
     */
    public synchronized void validateStrictSequence(long seq, String direction, String suite) {
        if (seq < expectedNextSeq) {
            eventLog.record(
                    DetectionEvent.AttackType.REPLAY,
                    DetectionEvent.Severity.HIGH,
                    "ReplayGuard",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    String.format("Replay detected on %s: received seq=%d, expected next seq=%d",
                            direction, seq, expectedNextSeq)
            );
            throw new SecurityException("Replay attack detected: sequence number " + seq + " already processed");
        } else if (seq > expectedNextSeq) {
            eventLog.record(
                    DetectionEvent.AttackType.REPLAY,
                    DetectionEvent.Severity.HIGH,
                    "ReplayGuard",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    String.format("Sequence gap / reordering detected on %s: received seq=%d, expected=%d",
                            direction, seq, expectedNextSeq)
            );
            throw new SecurityException("Record sequence violation: expected seq " + expectedNextSeq + ", got " + seq);
        }
        expectedNextSeq++;
    }

    /**
     * Sliding-window mode: tolerates minor network packet reordering while
     * strictly rejecting any duplicate sequence number.
     */
    public synchronized void validateWindowedSequence(long seq, String direction, String suite) {
        if (seq < 0) {
            throw new SecurityException("Negative sequence number: " + seq);
        }

        if (windowMaxSeq == -1) {
            windowMaxSeq = seq;
            receivedWindow.set(0);
            return;
        }

        if (seq > windowMaxSeq) {
            long diff = seq - windowMaxSeq;
            if (diff >= windowSize) {
                receivedWindow.clear();
            } else {
                // Shift window
                for (int i = windowSize - 1; i >= diff; i--) {
                    receivedWindow.set(i, receivedWindow.get((int) (i - diff)));
                }
                for (int i = 0; i < diff && i < windowSize; i++) {
                    receivedWindow.clear(i);
                }
            }
            windowMaxSeq = seq;
            receivedWindow.set(0);
        } else {
            long diff = windowMaxSeq - seq;
            if (diff >= windowSize) {
                eventLog.record(
                        DetectionEvent.AttackType.REPLAY,
                        DetectionEvent.Severity.HIGH,
                        "ReplayGuard",
                        suite,
                        DetectionEvent.Action.BLOCKED,
                        String.format("Packet too old / replayed on %s: seq=%d (windowMax=%d)",
                                direction, seq, windowMaxSeq)
                );
                throw new SecurityException("Replay attack detected: record seq " + seq + " is outside sliding window");
            }
            if (receivedWindow.get((int) diff)) {
                eventLog.record(
                        DetectionEvent.AttackType.REPLAY,
                        DetectionEvent.Severity.HIGH,
                        "ReplayGuard",
                        suite,
                        DetectionEvent.Action.BLOCKED,
                        String.format("Duplicate packet replayed on %s: seq=%d", direction, seq)
                );
                throw new SecurityException("Replay attack detected: duplicate sequence number " + seq);
            }
            receivedWindow.set((int) diff);
        }
    }

    /**
     * Validates record freshness against maximum clock skew.
     */
    public void validateTimestamp(Instant recordTimestamp, Duration maxSkew, String suite) {
        Instant now = Instant.now();
        Duration diff = Duration.between(recordTimestamp, now).abs();
        if (diff.compareTo(maxSkew) > 0) {
            eventLog.record(
                    DetectionEvent.AttackType.REPLAY,
                    DetectionEvent.Severity.MEDIUM,
                    "ReplayGuard",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    String.format("Stale record timestamp: %s (difference of %s exceeds allowed %s)",
                            recordTimestamp, diff, maxSkew)
            );
            throw new SecurityException("Replay attack detected: record timestamp expired");
        }
    }

    public synchronized long getExpectedNextSeq() {
        return expectedNextSeq;
    }

    public synchronized void reset() {
        expectedNextSeq = 0;
        windowMaxSeq = -1;
        receivedWindow.clear();
    }
}
