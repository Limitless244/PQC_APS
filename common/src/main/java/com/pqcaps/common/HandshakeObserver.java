package com.pqcaps.common;

import java.time.Instant;

/**
 * Observer hook for monitoring TLS handshake progress without leaking secrets.
 */
@FunctionalInterface
public interface HandshakeObserver {

    HandshakeObserver NOOP = (stepName, direction, messageBytes, hex4, outcome, timestamp) -> {};

    /**
     * Called when a handshake step occurs.
     *
     * @param stepName     name of the step (e.g. "ClientHello", "ServerHello", "SignatureCheck", "ClientFinished", "ServerFinished", "ChannelEstablished")
     * @param direction    direction of message flow ("CLIENT_TO_SERVER", "SERVER_TO_CLIENT", "CLIENT", "SERVER", "BOTH")
     * @param messageBytes size of message or cryptographic primitive in bytes
     * @param hex4         first 4 bytes of public identifier in hex (strictly never secrets or private keys)
     * @param outcome      outcome status ("OK", "BLOCKED", "FAILED", "SECURE")
     * @param timestamp    timestamp of event occurrence
     */
    void onHandshakeStep(String stepName, String direction, int messageBytes, String hex4, String outcome, Instant timestamp);
}
