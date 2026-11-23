package com.pqcaps.attack;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages 96-bit AES-GCM nonces, enforces monotonicity, detects reuse, and enforces rekeying.
 *
 * <p>AES-GCM Nonce Structure (96 bits = 12 bytes):
 * <ul>
 *   <li>Bytes [0..3]: 32-bit random salt / direction prefix generated at session start.</li>
 *   <li>Bytes [4..11]: 64-bit big-endian monotonic invocation counter.</li>
 * </ul>
 *
 * <p>Enforcements:
 * <ul>
 *   <li>Refuses duplicate nonces; throws {@link NonceReuseException}.</li>
 *   <li>Enforces a maximum message limit before requiring session rekeying (throwing {@link RekeyRequiredException}).</li>
 * </ul>
 */
public final class NonceManager {

    public static final int NONCE_LEN = 12;
    public static final long DEFAULT_MAX_MESSAGES = 1L << 24; // 16,777,216 messages

    private final EventLog eventLog;
    private final byte[] saltPrefix;
    private final AtomicLong counter = new AtomicLong(0);
    private final long maxMessages;
    private final Set<String> seenNonces = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public NonceManager() {
        this(DEFAULT_MAX_MESSAGES, EventLog.getInstance());
    }

    public NonceManager(long maxMessages) {
        this(maxMessages, EventLog.getInstance());
    }

    public NonceManager(long maxMessages, EventLog eventLog) {
        this.maxMessages = maxMessages;
        this.eventLog   = eventLog;
        this.saltPrefix = new byte[4];
        new SecureRandom().nextBytes(this.saltPrefix);
    }

    /**
     * Generates the next monotonic 12-byte GCM nonce.
     */
    public byte[] nextNonce(String suite) {
        long seq = counter.getAndIncrement();
        if (seq >= maxMessages) {
            eventLog.record(
                    DetectionEvent.AttackType.NONCE_REUSE,
                    DetectionEvent.Severity.HIGH,
                    "NonceManager",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    String.format("Session key exhaustion: message limit %d reached. Rekeying required.", maxMessages)
            );
            throw new RekeyRequiredException("Session message limit (" + maxMessages + ") reached: channel must rekey");
        }

        byte[] nonce = formatNonce(saltPrefix, seq);
        String hexKey = hex(nonce);
        if (!seenNonces.add(hexKey)) {
            eventLog.record(
                    DetectionEvent.AttackType.NONCE_REUSE,
                    DetectionEvent.Severity.HIGH,
                    "NonceManager",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    "CRITICAL: Nonce collision detected for nonce=" + hexKey
            );
            throw new NonceReuseException("Fatal nonce reuse detected: " + hexKey);
        }
        return nonce;
    }

    /**
     * Validates that an incoming nonce has not been seen before.
     */
    public void recordReceivedNonce(byte[] nonce, String suite) {
        if (nonce == null || nonce.length != NONCE_LEN) {
            throw new IllegalArgumentException("Invalid GCM nonce length: expected 12 bytes");
        }
        String hexKey = hex(nonce);
        if (!seenNonces.add(hexKey)) {
            eventLog.record(
                    DetectionEvent.AttackType.NONCE_REUSE,
                    DetectionEvent.Severity.HIGH,
                    "NonceManager",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    "Inbound nonce reuse detected for nonce=" + hexKey
            );
            throw new NonceReuseException("Inbound nonce reuse detected: " + hexKey);
        }
    }

    public boolean isRekeyNeeded() {
        return counter.get() >= maxMessages;
    }

    public long getCurrentCounter() {
        return counter.get();
    }

    public static byte[] formatNonce(byte[] prefix4, long counter64) {
        ByteBuffer buf = ByteBuffer.allocate(NONCE_LEN);
        buf.put(prefix4);
        buf.putLong(counter64);
        return buf.array();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
