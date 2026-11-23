package com.pqcaps.attack;

/**
 * Thrown when a secure channel has reached its maximum message counter threshold
 * and must undergo key renegotiation before further records may be processed.
 */
public class RekeyRequiredException extends SecurityException {
    public RekeyRequiredException(String message) {
        super(message);
    }
}
