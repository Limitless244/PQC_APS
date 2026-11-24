package com.pqcaps.chatlab;

/**
 * Strict validator enforcing that all network connections and binds use 127.0.0.1 only.
 */
public final class HostValidator {

    public static final String LOCALHOST_IP = "127.0.0.1";

    private HostValidator() {}

    public static void validateHost(String host) {
        if (host == null || !LOCALHOST_IP.equals(host.trim())) {
            throw new SecurityException("Host rejected: only " + LOCALHOST_IP + " is permitted (refused: '" + host + "')");
        }
    }
}
