package com.pqcaps.attack;

/**
 * Thrown when an attempt to encrypt or decrypt with a reused nonce is detected.
 */
public class NonceReuseException extends SecurityException {
    public NonceReuseException(String message) {
        super(message);
    }
}
