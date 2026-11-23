package com.pqcaps.common;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Decoupled event dispatcher allowing lower-level modules (common, classical, secure-channel)
 * to emit security detection events without creating circular dependencies on attack-engine.
 */
public final class SecurityEventSink {

    @FunctionalInterface
    public interface Listener {
        void onEvent(String attackType, String severity, String component, String suite, String action, String detail);
    }

    private static final List<Listener> LISTENERS = new CopyOnWriteArrayList<>();

    private SecurityEventSink() {}

    public static void register(Listener listener) {
        if (listener != null) {
            LISTENERS.add(listener);
        }
    }

    public static void emit(String attackType, String severity, String component, String suite, String action, String detail) {
        for (Listener l : LISTENERS) {
            try {
                l.onEvent(attackType, severity, component, suite, action, detail);
            } catch (Exception ignored) {}
        }
    }
}
