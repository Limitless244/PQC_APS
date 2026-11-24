package com.pqcaps.chatlab;

import java.util.List;

/**
 * Valid modes for Client and Server in the Chat Lab.
 */
public final class ChatMode {

    public static final String CLASSICAL_VULNERABLE = "CLASSICAL-VULNERABLE";
    public static final String CLASSICAL_HARDENED   = "CLASSICAL-HARDENED";
    public static final String HYBRID               = "HYBRID";

    public static final List<String> ALL_MODES = List.of(
            CLASSICAL_VULNERABLE,
            CLASSICAL_HARDENED,
            HYBRID
    );

    private ChatMode() {}

    public static String normalize(String mode) {
        if (mode == null || mode.isBlank()) {
            return HYBRID;
        }
        String upper = mode.trim().toUpperCase();
        if (!ALL_MODES.contains(upper)) {
            throw new IllegalArgumentException("Invalid mode: '" + mode + "'. Allowed modes: " + ALL_MODES);
        }
        return upper;
    }
}
