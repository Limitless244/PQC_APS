package com.pqcaps.common;

import java.time.Instant;

/**
 * Thread-safe context manager holding the active HandshakeObserver.
 */
public final class HandshakeObserverContext {

    private static volatile HandshakeObserver globalObserver = HandshakeObserver.NOOP;
    private static final ThreadLocal<HandshakeObserver> threadObserver = new ThreadLocal<>();

    private HandshakeObserverContext() {}

    public static void setGlobalObserver(HandshakeObserver observer) {
        globalObserver = (observer != null) ? observer : HandshakeObserver.NOOP;
    }

    public static void setThreadObserver(HandshakeObserver observer) {
        if (observer == null) {
            threadObserver.remove();
        } else {
            threadObserver.set(observer);
        }
    }

    public static HandshakeObserver current() {
        HandshakeObserver local = threadObserver.get();
        return (local != null) ? local : globalObserver;
    }

    public static void emit(String stepName, String direction, int messageBytes, String hex4, String outcome) {
        current().onHandshakeStep(stepName, direction, messageBytes, hex4, outcome, Instant.now());
    }
}
