package com.pqcaps.common;

import java.io.Serial;
import java.io.Serializable;

/**
 * Key confirmation message sent by the client after receiving ServerHello.
 *
 * <p>{@code Finished = HMAC-SHA256(finished_key, transcript_hash)}
 *
 * <p>Why Finished is critical in Post-Quantum KEM handshakes:
 * ML-KEM provides IND-CCA2 security using implicit rejection: if an active attacker
 * tampers with the KEM ciphertext in transit, decapsulation does NOT fail or throw an exception;
 * it silently outputs a different, pseudo-random shared secret. Without a Finished message,
 * data transmission would proceed with mismatched keys, leaking error information.
 * The Finished message provides mutual key confirmation: both parties prove they derived
 * identical session keys over an untampered transcript before any application payload is sent.
 *
 * @param verifyData 32-byte HMAC-SHA256 authentication tag over the handshake transcript
 */
public record FinishedMessage(byte[] verifyData) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public String toString() {
        return "FinishedMessage{verifyData=" + hex4(verifyData) + "...}";
    }

    private static String hex4(byte[] b) {
        return (b == null || b.length < 4) ? "null"
                : String.format("%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    }
}
