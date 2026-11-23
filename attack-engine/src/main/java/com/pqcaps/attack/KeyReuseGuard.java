package com.pqcaps.attack;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ephemeral Key Registry and Forward Secrecy Enforcer.
 *
 * <p>Forward secrecy requires that ephemeral keypairs be generated uniquely for
 * every single session. Reusing an ephemeral key across sessions compromises
 * past sessions if the private key is later leaked.
 *
 * <p>{@code KeyReuseGuard} maintains a fingerprint registry of recently seen
 * ephemeral public keys and immediately rejects duplicate keys.
 */
public final class KeyReuseGuard {

    private final EventLog eventLog;
    private final Set<String> registeredFingerprints = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public KeyReuseGuard() {
        this(EventLog.getInstance());
    }

    public KeyReuseGuard(EventLog eventLog) {
        this.eventLog = eventLog;
    }

    /**
     * Checks if an ephemeral public key was seen before. If fresh, registers it.
     * If reused, emits a {@code KEY_REUSE} event and throws {@link SecurityException}.
     *
     * @param ephemeralPubKey encoded ephemeral public key bytes
     * @param suite           active algorithm suite
     */
    public void registerEphemeralKey(byte[] ephemeralPubKey, String suite) {
        if (ephemeralPubKey == null || ephemeralPubKey.length == 0) {
            return;
        }

        String fingerprint = fingerprint(ephemeralPubKey);
        if (!registeredFingerprints.add(fingerprint)) {
            eventLog.record(
                    DetectionEvent.AttackType.KEY_REUSE,
                    DetectionEvent.Severity.HIGH,
                    "KeyReuseGuard",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    "Ephemeral public key reuse detected! Fingerprint: " + fingerprint + " (Forward secrecy violated)"
            );
            throw new SecurityException("Ephemeral key reuse detected! Forward secrecy violation for key " + fingerprint);
        }
    }

    public boolean isRegistered(byte[] ephemeralPubKey) {
        if (ephemeralPubKey == null) return false;
        return registeredFingerprints.contains(fingerprint(ephemeralPubKey));
    }

    public void clear() {
        registeredFingerprints.clear();
    }

    private static String fingerprint(byte[] key) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(key);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
