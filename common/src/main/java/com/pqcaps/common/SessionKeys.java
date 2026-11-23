package com.pqcaps.common;

import java.util.Arrays;

/**
 * Session keys derived at the end of the handshake.
 *
 * <p>Two separate 32-byte AES-256 keys are derived: one for each direction.
 * In Phase 3, an additional 32-byte {@code finishedKey} is derived for Finished message verification.
 *
 * <p><b>Zeroization</b>: call {@link #zeroize()} as soon as the channel is closed.
 *
 * @param clientToServer 32-byte key: client encrypts with this, server decrypts
 * @param serverToClient 32-byte key: server encrypts with this, client decrypts
 * @param finishedKey    32-byte key: used for HMAC Finished key confirmation (Phase 3)
 */
public record SessionKeys(byte[] clientToServer, byte[] serverToClient, byte[] finishedKey) {

    /**
     * Backward-compatible 2-argument constructor for Phase 1 & 2 baseline.
     */
    public SessionKeys(byte[] clientToServer, byte[] serverToClient) {
        this(clientToServer, serverToClient, null);
    }

    /**
     * Overwrites key arrays with zero bytes, removing key material from memory.
     * Call this in a {@code finally} block when the session ends.
     */
    public void zeroize() {
        if (clientToServer != null) {
            Arrays.fill(clientToServer, (byte) 0);
        }
        if (serverToClient != null) {
            Arrays.fill(serverToClient, (byte) 0);
        }
        if (finishedKey != null) {
            Arrays.fill(finishedKey, (byte) 0);
        }
    }

    @Override
    public String toString() {
        return String.format("SessionKeys{c2s=%s..., s2c=%s..., fin=%s...}",
                hex4(clientToServer), hex4(serverToClient), hex4(finishedKey));
    }

    private static String hex4(byte[] b) {
        return (b == null || b.length < 4) ? "null"
                : String.format("%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    }
}
