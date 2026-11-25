package com.pqcaps.chatlab.service;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attack.EventLog;
import com.pqcaps.attack.ReplayGuard;
import com.pqcaps.attack.TamperGuard;
import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.channel.HybridHandshake;
import com.pqcaps.chatlab.ChatMode;
import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.classical.AesGcmCipher;
import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.EncryptedRecord;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Bob's Server TCP Service running on 127.0.0.1:9001 (or configured port).
 * Implements real handshakes and defence guards (ReplayGuard, TamperGuard, Downgrade policy).
 */
@Service
public class ChatLabServerService {

    private static final Logger log = LoggerFactory.getLogger(ChatLabServerService.class);

    private final List<ChatMessageRecord> receivedMessages = new CopyOnWriteArrayList<>();
    private final List<Consumer<ChatMessageRecord>> messageListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<DetectionEvent>> eventListeners = new CopyOnWriteArrayList<>();

    private volatile String currentMode = ChatMode.HYBRID;
    private volatile boolean rejectClassical = true;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong messageCounter = new AtomicLong(0);

    private final AtomicReference<ObjectOutputStream> activeOut = new AtomicReference<>(null);
    private final AtomicReference<SessionKeys> activeSessionKeys = new AtomicReference<>(null);
    private final AtomicReference<AesGcmCipher> activeCipher = new AtomicReference<>(null);
    private final AtomicLong serverSendSeq = new AtomicLong(0);

    private ServerSocket serverSocket;
    private int tcpPort;
    private Thread listenerThread;

    private final KeyPair serverIdentityMlDsa;
    private final KeyPair serverIdentityRsa;

    public ChatLabServerService(@Value("${server.tcp.port:9001}") int tcpPort) {
        this.tcpPort = tcpPort;
        this.serverIdentityMlDsa = new MlDsaSignatureScheme().generateKeyPair();
        this.serverIdentityRsa   = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();
        savePublicKeysToDisk();
    }

    public boolean hasActiveClient() {
        return activeOut.get() != null;
    }

    public synchronized void start() throws IOException {
        start(this.tcpPort, this.currentMode);
    }

    public synchronized void start(int port, String mode) throws IOException {
        if (running.get()) {
            if (this.tcpPort == port && this.currentMode.equalsIgnoreCase(mode)) {
                return;
            }
            stop();
        }

        this.currentMode = ChatMode.normalize(mode);
        HostValidator.validateHost(HostValidator.LOCALHOST_IP);

        this.serverSocket = new ServerSocket(port, 50, InetAddress.getByName(HostValidator.LOCALHOST_IP));
        this.tcpPort = this.serverSocket.getLocalPort();
        this.running.set(true);

        log.info("[SERVER-BOB] Started TCP server on 127.0.0.1:{} (mode: {})", this.tcpPort, this.currentMode);

        this.listenerThread = new Thread(this::listenLoop, "chat-lab-server-listener");
        this.listenerThread.setDaemon(true);
        this.listenerThread.start();
    }

    public synchronized void stop() {
        running.set(false);
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {}
        }
        if (listenerThread != null) {
            listenerThread.interrupt();
        }
        log.info("[SERVER-BOB] Stopped TCP server");
    }

    public synchronized void reset() {
        this.activeOut.set(null);
        this.activeSessionKeys.set(null);
        this.activeCipher.set(null);
        receivedMessages.clear();
        messageCounter.set(0);
        log.info("[SERVER-BOB] Reset server session state");
    }

    public synchronized void setMode(String mode) {
        this.currentMode = ChatMode.normalize(mode);
        log.info("[SERVER-BOB] Mode set to {}", this.currentMode);
    }

    public String getCurrentMode() {
        return currentMode;
    }

    public int getTcpPort() {
        return tcpPort;
    }

    public boolean isRunning() {
        return running.get();
    }

    public boolean isRejectClassical() {
        return rejectClassical;
    }

    public void setRejectClassical(boolean rejectClassical) {
        this.rejectClassical = rejectClassical;
        log.info("[SERVER-BOB] rejectClassical policy updated to: {}", rejectClassical);
    }

    public List<ChatMessageRecord> getReceivedMessages() {
        return Collections.unmodifiableList(receivedMessages);
    }

    public List<DetectionEvent> getDetectionEvents() {
        return EventLog.getInstance().getEvents();
    }

    public PublicKey getServerIdentityMlDsaPublic() {
        return serverIdentityMlDsa.getPublic();
    }

    public PublicKey getServerIdentityRsaPublic() {
        return serverIdentityRsa.getPublic();
    }

    public void addMessageListener(Consumer<ChatMessageRecord> listener) {
        messageListeners.add(listener);
    }

    public void addEventListener(Consumer<DetectionEvent> listener) {
        eventListeners.add(listener);
    }

    private void listenLoop() {
        while (running.get() && !serverSocket.isClosed()) {
            try {
                Socket clientConn = serverSocket.accept();
                HostValidator.validateHost(clientConn.getInetAddress().getHostAddress());
                Thread sessionThread = new Thread(() -> handleConnection(clientConn), "chat-lab-server-session");
                sessionThread.setDaemon(true);
                sessionThread.start();
            } catch (IOException e) {
                if (!running.get()) break;
            }
        }
    }

    private void handleConnection(Socket socket) {
        log.info("[SERVER-BOB] New connection from {}", socket.getRemoteSocketAddress());
        ObjectInputStream in = null;
        ObjectOutputStream out = null;

        try {
            in = new ObjectInputStream(socket.getInputStream());
            out = new ObjectOutputStream(socket.getOutputStream());
            out.flush();

            String mode = this.currentMode;
            SessionKeys sessionKeys;
            String chosenSuite;
            final ReplayGuard replayGuard = new ReplayGuard();
            final TamperGuard tamperGuard = new TamperGuard();
            AesGcmCipher cipher = new AesGcmCipher();

            if (ChatMode.CLASSICAL_VULNERABLE.equalsIgnoreCase(mode)) {
                // VULNERABLE: No sequence validation, no tamper telemetry
                ClassicalHandshake.HandshakeOutcome outcome =
                        ClassicalHandshake.serverHandshakeFull(in, out, HandshakeConfig.vulnerable(), serverIdentityRsa);
                sessionKeys = outcome.sessionKeys();
                chosenSuite = outcome.chosenSuite();
            } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
                // HARDENED CLASSICAL: Pinned RSA identity, ReplayGuard, TamperGuard
                ClassicalHandshake.HandshakeOutcome outcome =
                        ClassicalHandshake.serverHandshakeFull(in, out, HandshakeConfig.hardened(), serverIdentityRsa);
                sessionKeys = outcome.sessionKeys();
                chosenSuite = outcome.chosenSuite();
            } else {
                // HYBRID: FIPS 203 ML-KEM-768 + X25519, FIPS 204 ML-DSA-65 identity, ReplayGuard, TamperGuard
                HybridHandshake.HandshakeOutcome outcome =
                        HybridHandshake.serverHandshake(out, in, serverIdentityMlDsa.getPrivate(), this.rejectClassical);
                sessionKeys = outcome.sessionKeys();
                chosenSuite = outcome.chosenSuite();
            }

            log.info("[SERVER-BOB] Handshake complete! Negotiated suite: {}", chosenSuite);
            this.activeOut.set(out);
            this.activeSessionKeys.set(sessionKeys);
            this.activeCipher.set(cipher);
            this.serverSendSeq.set(0);

            // ── Record Phase Loop ──────────────────────────────────────────
            while (running.get() && !socket.isClosed()) {
                Object obj;
                try {
                    obj = in.readObject();
                } catch (EOFException | java.net.SocketException e) {
                    break;
                }

                if (!(obj instanceof EncryptedRecord record)) {
                    continue;
                }

                String hex4Ct = hex4(record.ciphertext());
                long seq = record.sequenceNumber();
                String msgId = "msg-" + messageCounter.incrementAndGet();

                if (ChatMode.CLASSICAL_VULNERABLE.equalsIgnoreCase(mode)) {
                    // Vulnerable mode: accept duplicate sequence numbers without checking!
                    byte[] aad = ClassicalSecureChannel.buildAad(seq);
                    try {
                        byte[] plain = cipher.decrypt(sessionKeys.clientToServer(), record.nonce(), aad, record.ciphertext());
                        String text = new String(plain, StandardCharsets.UTF_8);
                        ChatMessageRecord rec = new ChatMessageRecord(
                                msgId, "Client", text, seq, "ACCEPTED", null, hex4Ct, Instant.now()
                        );
                        receivedMessages.add(rec);
                        notifyMessage(rec);
                        log.info("[SERVER] [VULNERABLE] Accepted record seq={} (\"{}\")", seq, text);

                        // Send ACK record back
                        sendAck(out, sessionKeys, cipher, serverSendSeq.getAndIncrement(), "ACK: " + text);
                    } catch (Exception e) {
                        // In vulnerable mode: raw GCM decryption error without security telemetry
                        ChatMessageRecord rec = new ChatMessageRecord(
                                msgId, "Client", "[DECRYPTION FAILED - RAW EXCEPTION]", seq,
                                "REJECTED (raw decryption exception)", null, hex4Ct, Instant.now()
                        );
                        receivedMessages.add(rec);
                        notifyMessage(rec);
                        log.warn("[SERVER] [VULNERABLE] GCM decryption error on record seq={}: {}", seq, e.getMessage());
                    }
                } else {
                    // Hardened / Hybrid mode: Enforce guards!
                    boolean sequenceOk = false;
                    try {
                        replayGuard.validateStrictSequence(seq, "C2S", mode);
                        sequenceOk = true;
                    } catch (SecurityException se) {
                        DetectionEvent ev = EventLog.getInstance().getLastEvent();
                        String guardName = "ReplayGuard";
                        ChatMessageRecord rec = new ChatMessageRecord(
                                msgId, "Client", "[REPLAY BLOCKED]", seq,
                                "REJECTED (" + se.getMessage() + ")", guardName, hex4Ct, Instant.now()
                        );
                        receivedMessages.add(rec);
                        notifyMessage(rec);
                        if (ev != null) notifyEvent(ev);
                        log.warn("[SERVER] Replay rejected at seq={}: {}", seq, se.getMessage());
                    }

                    if (sequenceOk) {
                        byte[] aad = ClassicalSecureChannel.buildAad(seq);
                        try {
                            byte[] plain = cipher.decrypt(sessionKeys.clientToServer(), record.nonce(), aad, record.ciphertext());
                            String text = new String(plain, StandardCharsets.UTF_8);
                            ChatMessageRecord rec = new ChatMessageRecord(
                                    msgId, "Client", text, seq, "ACCEPTED (seq=" + seq + " verified)", null, hex4Ct, Instant.now()
                            );
                            receivedMessages.add(rec);
                            notifyMessage(rec);
                            log.info("[SERVER] Accepted verified record seq={} (\"{}\")", seq, text);

                            // Send ACK record back
                            sendAck(out, sessionKeys, cipher, serverSendSeq.getAndIncrement(), "ACK: " + text);
                        } catch (Exception e) {
                            SecurityException secEx = tamperGuard.handleAeadTampering(e, seq, record.nonce(), mode);
                            DetectionEvent ev = EventLog.getInstance().getLastEvent();
                            String guardName = "TamperGuard";
                            ChatMessageRecord rec = new ChatMessageRecord(
                                    msgId, "Client", "[TAMPER BLOCKED]", seq,
                                    "REJECTED (" + secEx.getMessage() + ")", guardName, hex4Ct, Instant.now()
                            );
                            receivedMessages.add(rec);
                            notifyMessage(rec);
                            if (ev != null) notifyEvent(ev);
                            log.warn("[SERVER] Tamper rejected at seq={}: {}", seq, secEx.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[SERVER-BOB] Connection ended: {}", e.getMessage());
        } finally {
            this.activeOut.set(null);
            this.activeSessionKeys.set(null);
            this.activeCipher.set(null);
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                socket.close();
            } catch (IOException ignored) {}
        }
    }

    private void sendAck(ObjectOutputStream out, SessionKeys keys, AesGcmCipher cipher, long seq, String ackText) {
        try {
            byte[] nonce = ClassicalSecureChannel.buildNonce(seq);
            byte[] aad = ClassicalSecureChannel.buildAad(seq);
            byte[] ct = cipher.encrypt(keys.serverToClient(), nonce, aad, ackText.getBytes(StandardCharsets.UTF_8));
            EncryptedRecord ackRecord = new EncryptedRecord(seq, nonce, ct);
            out.writeObject(ackRecord);
            out.flush();
        } catch (Exception e) {
            log.debug("[SERVER-BOB] Failed to send ACK: {}", e.getMessage());
        }
    }

    public synchronized ChatMessageRecord sendServerMessage(String text) throws IOException {
        ObjectOutputStream out = activeOut.get();
        SessionKeys keys = activeSessionKeys.get();
        AesGcmCipher cipher = activeCipher.get();
        if (out == null || keys == null || cipher == null) {
            throw new IllegalStateException("Server has no active client connection. Connect client first.");
        }
        long seq = serverSendSeq.getAndIncrement();
        byte[] nonce = ClassicalSecureChannel.buildNonce(seq);
        byte[] aad = ClassicalSecureChannel.buildAad(seq);
        byte[] ct = cipher.encrypt(keys.serverToClient(), nonce, aad, text.getBytes(StandardCharsets.UTF_8));
        EncryptedRecord record = new EncryptedRecord(seq, nonce, ct);
        synchronized (out) {
            out.writeObject(record);
            out.flush();
        }
        String msgId = "srv-" + messageCounter.incrementAndGet();
        ChatMessageRecord rec = new ChatMessageRecord(
                msgId, "Server", text, seq, "SENT (seq=" + seq + ")", null, hex4(ct), Instant.now()
        );
        receivedMessages.add(rec);
        notifyMessage(rec);
        log.info("[SERVER] Sent message seq={} (\"{}\") to client", seq, text);
        return rec;
    }

    private void notifyMessage(ChatMessageRecord rec) {
        for (Consumer<ChatMessageRecord> listener : messageListeners) {
            try {
                listener.accept(rec);
            } catch (Exception ignored) {}
        }
    }

    private void notifyEvent(DetectionEvent ev) {
        for (Consumer<DetectionEvent> listener : eventListeners) {
            try {
                listener.accept(ev);
            } catch (Exception ignored) {}
        }
    }

    private void savePublicKeysToDisk() {
        try {
            Path keysDir = com.pqcaps.common.DataPaths.resolve("chat-lab/server-keys");
            Files.createDirectories(keysDir);
            Files.write(keysDir.resolve("server_mldsa65.pub"), serverIdentityMlDsa.getPublic().getEncoded());
            Files.write(keysDir.resolve("server_rsa.pub"), serverIdentityRsa.getPublic().getEncoded());
        } catch (Exception e) {
            log.debug("[SERVER-BOB] Could not write public keys to disk: {}", e.getMessage());
        }
    }

    private static String hex4(byte[] b) {
        if (b == null || b.length < 4) return "null";
        return String.format("%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    }
}
