package com.pqcaps.classical;

import com.pqcaps.common.EncryptedRecord;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SecurityEventSink;
import com.pqcaps.common.SessionKeys;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * AES-256-GCM record layer for the classical secure channel.
 */
public final class ClassicalSecureChannel implements Closeable {

    private static final int NONCE_LEN = 12;

    private final SessionKeys     keys;
    private final boolean         isClient;
    private final ObjectOutputStream wireOut;
    private final ObjectInputStream  wireIn;
    private final HandshakeConfig    config;
    private final AesGcmCipher       cipher;

    private long sendSeq = 0;
    private long recvSeq = 0;

    public ClassicalSecureChannel(Socket socket, SessionKeys keys,
                                   boolean isClient, HandshakeConfig config) throws IOException {
        this.keys     = keys;
        this.isClient = isClient;
        this.config   = config;
        this.cipher   = new AesGcmCipher();
        this.wireOut = new ObjectOutputStream(socket.getOutputStream());
        this.wireOut.flush();
        this.wireIn  = new ObjectInputStream(socket.getInputStream());
    }

    public ClassicalSecureChannel(ObjectOutputStream out, ObjectInputStream in,
                                   SessionKeys keys, boolean isClient, HandshakeConfig config) {
        this.keys     = keys;
        this.isClient = isClient;
        this.config   = config;
        this.cipher   = new AesGcmCipher();
        this.wireOut  = out;
        this.wireIn   = in;
    }

    public void send(byte[] plaintext) throws IOException {
        byte[] sendKey = isClient ? keys.clientToServer() : keys.serverToClient();

        byte[] nonce = buildNonce(sendSeq);
        byte[] aad   = buildAad(sendSeq);

        byte[] ct = cipher.encrypt(sendKey, nonce, aad, plaintext);
        EncryptedRecord record = new EncryptedRecord(sendSeq, nonce, ct);
        wireOut.writeObject(record);
        wireOut.flush();
        sendSeq++;
    }

    public byte[] receive() throws IOException, ClassNotFoundException {
        EncryptedRecord record = (EncryptedRecord) wireIn.readObject();

        if (!config.isSkipSequenceCheck()) {
            if (record.sequenceNumber() != recvSeq) {
                SecurityEventSink.emit(
                        "REPLAY",
                        "HIGH",
                        "ClassicalSecureChannel",
                        "CLASSICAL",
                        "BLOCKED",
                        "Sequence number mismatch -- possible replay! expected=" + recvSeq + " got=" + record.sequenceNumber()
                );
                throw new SecurityException(
                        "Sequence number mismatch -- possible replay! "
                        + "expected=" + recvSeq + " got=" + record.sequenceNumber());
            }
        }

        byte[] recvKey = isClient ? keys.serverToClient() : keys.clientToServer();
        byte[] aad     = buildAad(record.sequenceNumber());
        byte[] plain;
        try {
            plain = cipher.decrypt(recvKey, record.nonce(), aad, record.ciphertext());
        } catch (Exception e) {
            if (config.isHardened()) {
                SecurityEventSink.emit(
                        "TAMPER",
                        "HIGH",
                        "ClassicalSecureChannel",
                        "CLASSICAL",
                        "BLOCKED",
                        "GCM authentication tag failure at record seq=" + record.sequenceNumber()
                );
            }
            throw new SecurityException("Record decryption failed", e);
        }
        recvSeq = record.sequenceNumber() + 1;
        return plain;
    }

    public void resetNonceCounterForTesting() {
        if (!config.isUnsafeNonceMode()) {
            SecurityEventSink.emit(
                    "NONCE_REUSE",
                    "HIGH",
                    "ClassicalSecureChannel",
                    "CLASSICAL",
                    "BLOCKED",
                    "Nonce counter reset refused -- unsafeNonceMode is disabled"
            );
            throw new IllegalStateException(
                    "Nonce counter reset refused -- unsafeNonceMode is disabled");
        }
        sendSeq = 0;
    }

    public static byte[] buildNonce(long seq) {
        byte[] nonce = new byte[NONCE_LEN];
        for (int i = 7; i >= 0; i--) {
            nonce[NONCE_LEN - 8 + (7 - i)] = (byte) ((seq >> (i * 8)) & 0xFF);
        }
        return nonce;
    }

    public static byte[] buildAad(long seq) {
        byte[] aad = new byte[8];
        for (int i = 7; i >= 0; i--) {
            aad[7 - i] = (byte) ((seq >> (i * 8)) & 0xFF);
        }
        return aad;
    }

    public long getSendSeq() { return sendSeq; }
    public long getRecvSeq() { return recvSeq; }

    @Override
    public void close() throws IOException {
        try {
            wireOut.close();
        } finally {
            wireIn.close();
        }
    }
}
