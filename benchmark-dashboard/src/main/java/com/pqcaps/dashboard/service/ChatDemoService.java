package com.pqcaps.dashboard.service;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.classical.AesGcmCipher;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.EncryptedRecord;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SecurityEventSink;
import com.pqcaps.common.SessionKeys;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class ChatDemoService {

    public record ChatSendResult(
            String sender,
            String message,
            long sequenceNumber,
            String ciphertextHexTruncated,
            String attackerView,
            String bobOutcome,
            String mode
    ) {
        /**
         * Returns the actual decrypted plaintext seen by the attacker in CLASSICAL-VULNERABLE mode.
         */
        public String attackerPlaintext() {
            if (attackerView != null && attackerView.startsWith("[MITM Intercepted Plaintext]: \"")) {
                return attackerView.substring("[MITM Intercepted Plaintext]: \"".length(), attackerView.length() - 1);
            }
            return attackerView;
        }
    }

    public record AttackerActionResult(
            String action,
            String outcome,
            String detail,
            String eventId,
            String mode
    ) {}

    private final ReentrantLock lock = new ReentrantLock();
    private final AesGcmCipher cipher = new AesGcmCipher();

    private String currentMode = "HYBRID";
    private SessionKeys sessionKeys;
    private SessionKeys attackerCompromisedKeys; // Only non-null in CLASSICAL-VULNERABLE MITM
    private long aliceSendSeq = 0;
    private long bobRecvSeq = 0;
    private EncryptedRecord lastRecord = null;
    private String lastPlaintext = null;

    public ChatDemoService() {
        initSession("HYBRID");
    }

    public synchronized void initSession(String mode) {
        if (mode == null || !List.of("CLASSICAL-VULNERABLE", "CLASSICAL-HARDENED", "HYBRID").contains(mode.toUpperCase())) {
            throw new IllegalArgumentException("Invalid chat mode: '" + mode + "'. Allowed: CLASSICAL-VULNERABLE, CLASSICAL-HARDENED, HYBRID");
        }
        this.currentMode = mode.toUpperCase();
        this.aliceSendSeq = 0;
        this.bobRecvSeq = 0;
        this.lastRecord = null;
        this.lastPlaintext = null;

        SecureRandom rng = new SecureRandom();
        byte[] c2s = new byte[32];
        byte[] s2c = new byte[32];
        rng.nextBytes(c2s);
        rng.nextBytes(s2c);
        this.sessionKeys = new SessionKeys(c2s, s2c);

        if ("CLASSICAL-VULNERABLE".equals(this.currentMode)) {
            // MITM holds copy of session keys in vulnerable classical mode
            this.attackerCompromisedKeys = this.sessionKeys;
        } else {
            this.attackerCompromisedKeys = null;
        }
    }

    public ChatSendResult sendMessage(String message) {
        lock.lock();
        try {
            if (message == null || message.isBlank()) {
                throw new IllegalArgumentException("Message content cannot be empty");
            }
            if (message.length() > 500) {
                throw new IllegalArgumentException("Message exceeds 500 characters limit");
            }

            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            byte[] nonce = ClassicalSecureChannel.buildNonce(aliceSendSeq);
            byte[] aad = ClassicalSecureChannel.buildAad(aliceSendSeq);

            byte[] ct = cipher.encrypt(sessionKeys.clientToServer(), nonce, aad, plaintext);
            EncryptedRecord record = new EncryptedRecord(aliceSendSeq, nonce, ct);
            this.lastRecord = record;
            this.lastPlaintext = message;

            long seq = aliceSendSeq++;

            // Truncated ciphertext hex (first 16 bytes)
            String ctHexTruncated = formatTruncatedHex(ct, 16);

            // Attacker observation
            String attackerView;
            if ("CLASSICAL-VULNERABLE".equals(currentMode) && attackerCompromisedKeys != null) {
                // VULN-4: Missing client key pinning allows the on-path MITM to terminate the handshake
                // with both client and server, obtaining session keys. The attacker intercepts the captured
                // on-wire EncryptedRecord and genuinely decrypts it using AES-GCM without hardcoded strings.
                byte[] intercepted = cipher.decrypt(
                        attackerCompromisedKeys.clientToServer(),
                        record.nonce(),
                        ClassicalSecureChannel.buildAad(record.sequenceNumber()),
                        record.ciphertext()
                );
                String actualDecryptedPlaintext = new String(intercepted, StandardCharsets.UTF_8);
                attackerView = "[MITM Intercepted Plaintext]: \"" + actualDecryptedPlaintext + "\"";
            } else {
                // Hybrid/Hardened: Attacker only sees encrypted ciphertext bytes
                attackerView = "[Encrypted Record seq=" + seq + "]: " + ctHexTruncated + " (" + ct.length + " bytes ciphertext)";
            }

            // Bob receives record
            bobRecvSeq++;
            String bobOutcome = "ACCEPTED (seq=" + seq + " verified)";

            return new ChatSendResult("Alice", message, seq, ctHexTruncated, attackerView, bobOutcome, currentMode);
        } finally {
            lock.unlock();
        }
    }

    public AttackerActionResult replayLastMessage() {
        lock.lock();
        try {
            if (lastRecord == null) {
                throw new IllegalStateException("No previous message available to replay");
            }

            if ("CLASSICAL-VULNERABLE".equals(currentMode)) {
                // Bob accepts duplicate without sequence checking!
                return new AttackerActionResult(
                        "REPLAY",
                        "SUCCEEDED",
                        "Replayed record seq=" + lastRecord.sequenceNumber() + " accepted by Bob without sequence check!",
                        null,
                        currentMode
                );
            } else {
                // Bob's channel has sequence checks active
                String eventId = UUID.randomUUID().toString();
                SecurityEventSink.emit(
                        "REPLAY",
                        "HIGH",
                        "ChatDemoChannel",
                        currentMode,
                        "BLOCKED",
                        "Sequence number mismatch -- replay attack thwarted! expected=" + bobRecvSeq + " got=" + lastRecord.sequenceNumber()
                );

                return new AttackerActionResult(
                        "REPLAY",
                        "BLOCKED",
                        "Replay of record seq=" + lastRecord.sequenceNumber() + " BLOCKED by sequence validation (expected seq=" + bobRecvSeq + ")",
                        eventId,
                        currentMode
                );
            }
        } finally {
            lock.unlock();
        }
    }

    public AttackerActionResult flipBit() {
        lock.lock();
        try {
            if (lastRecord == null) {
                throw new IllegalStateException("No previous message available to tamper");
            }

            byte[] tamperedCt = lastRecord.ciphertext().clone();
            tamperedCt[0] ^= 0x01; // Flip first bit!

            byte[] nonce = lastRecord.nonce();
            byte[] aad = ClassicalSecureChannel.buildAad(lastRecord.sequenceNumber());

            if ("CLASSICAL-VULNERABLE".equals(currentMode)) {
                // Fails decryption with raw exception, but zero security telemetry is emitted
                return new AttackerActionResult(
                        "TAMPER",
                        "SUCCEEDED",
                        "Ciphertext bit flipped -> GCM decryption error triggered without defensive event telemetry (error oracle leak risk)",
                        null,
                        currentMode
                );
            } else {
                // Hardened / Hybrid emits TAMPER event and blocks
                String eventId = UUID.randomUUID().toString();
                SecurityEventSink.emit(
                        "TAMPER",
                        "HIGH",
                        "ChatDemoChannel",
                        currentMode,
                        "BLOCKED",
                        "GCM authentication tag verification failed on tampered record seq=" + lastRecord.sequenceNumber()
                );

                return new AttackerActionResult(
                        "TAMPER",
                        "BLOCKED",
                        "Tampering BLOCKED by TamperGuard: GCM authentication tag mismatch detected on record seq=" + lastRecord.sequenceNumber(),
                        eventId,
                        currentMode
                );
            }
        } finally {
            lock.unlock();
        }
    }

    public String getCurrentMode() {
        return currentMode;
    }

    private String formatTruncatedHex(byte[] b, int maxBytes) {
        if (b == null || b.length == 0) return "empty";
        int len = Math.min(b.length, maxBytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        if (b.length > maxBytes) {
            sb.append("... [").append(b.length).append(" bytes]");
        }
        return sb.toString();
    }
}
