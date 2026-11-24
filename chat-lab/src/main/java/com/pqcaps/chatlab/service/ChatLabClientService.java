package com.pqcaps.chatlab.service;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.channel.HybridHandshake;
import com.pqcaps.chatlab.ChatMode;
import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.chatlab.model.HandshakeStepRecord;
import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.HandshakeObserver;
import com.pqcaps.common.HandshakeObserverContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Alice's Client TCP Service running on web :8081.
 * Connects to the Attacker proxy (127.0.0.1:9000) or direct to Server (127.0.0.1:9001).
 * Executes real cryptographic handshakes and records live 8-step handshake telemetry.
 */
@Service
public class ChatLabClientService {

    private static final Logger log = LoggerFactory.getLogger(ChatLabClientService.class);

    private final List<HandshakeStepRecord> handshakeSteps = new CopyOnWriteArrayList<>();
    private final List<ChatMessageRecord> chatHistory = new CopyOnWriteArrayList<>();
    private final List<Consumer<HandshakeStepRecord>> stepListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<ChatMessageRecord>> messageListeners = new CopyOnWriteArrayList<>();

    private volatile String currentMode = ChatMode.HYBRID;
    private volatile String connectionStatus = "DISCONNECTED"; // DISCONNECTED, CONNECTING, CONNECTED, FAILED
    private volatile String chosenSuite = "NONE";
    private volatile boolean keyPinned = false;
    private volatile String lastError = null;

    private int targetPort;
    private String targetHost = HostValidator.LOCALHOST_IP;

    private Socket clientSocket;
    private ObjectOutputStream socketOut;
    private ObjectInputStream socketIn;
    private ClassicalSecureChannel secureChannel;
    private final AtomicLong messageCounter = new AtomicLong(0);
    private final AtomicBoolean connected = new AtomicBoolean(false);

    private PublicKey pinnedServerKeyMlDsa;
    private PublicKey pinnedServerKeyRsa;

    public ChatLabClientService(@Value("${client.tcp.targetPort:9000}") int targetPort) {
        this.targetPort = targetPort;
        loadPinnedKeysFromDisk();
    }

    public synchronized void setMode(String mode) {
        this.currentMode = ChatMode.normalize(mode);
        log.info("[CLIENT-ALICE] Mode set to {}", this.currentMode);
    }

    public String getCurrentMode() {
        return currentMode;
    }

    public synchronized void setTargetPort(int port) {
        this.targetPort = port;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public synchronized void connect() throws Exception {
        connect(this.targetHost, this.targetPort, this.currentMode, null);
    }

    public synchronized void connect(String host, int port, String mode, PublicKey explicitPinnedKey) throws Exception {
        HostValidator.validateHost(host);
        this.targetHost = host;
        this.targetPort = port;
        this.currentMode = ChatMode.normalize(mode);

        disconnect();

        this.connectionStatus = "CONNECTING";
        this.lastError = null;
        this.chosenSuite = "NONE";
        this.handshakeSteps.clear();

        log.info("[CLIENT-ALICE] Initiating connection to {}:{} (mode: {})", host, port, this.currentMode);

        HandshakeObserver observer = (stepName, direction, messageBytes, hex4, outcome, timestamp) -> {
            HandshakeStepRecord rec = new HandshakeStepRecord(stepName, direction, messageBytes, hex4, outcome, timestamp);
            handshakeSteps.add(rec);
            for (Consumer<HandshakeStepRecord> listener : stepListeners) {
                try { listener.accept(rec); } catch (Exception ignored) {}
            }
        };

        HandshakeObserverContext.setGlobalObserver(observer);

        try {
            this.clientSocket = new Socket(host, port);
            this.clientSocket.setSoTimeout(5000);
            this.socketOut = new ObjectOutputStream(clientSocket.getOutputStream());
            this.socketOut.flush();
            this.socketIn = new ObjectInputStream(clientSocket.getInputStream());

            if (ChatMode.CLASSICAL_VULNERABLE.equalsIgnoreCase(this.currentMode)) {
                // VULNERABLE: Skip server public-key pinning (VULN-4)
                this.keyPinned = false;
                ClassicalHandshake.HandshakeOutcome outcome = ClassicalHandshake.clientHandshakeFull(
                        socketOut, socketIn, HandshakeConfig.vulnerable(), null, List.of("CLASSICAL")
                );
                this.chosenSuite = outcome.chosenSuite();
                this.secureChannel = new ClassicalSecureChannel(
                        socketOut, socketIn, outcome.sessionKeys(), true, HandshakeConfig.vulnerable()
                );
            } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(this.currentMode)) {
                // HARDENED CLASSICAL: Pinned RSA key, signed transcript covering suite list
                PublicKey pinnedKey = explicitPinnedKey != null ? explicitPinnedKey : getOrLoadPinnedRsaKey();
                this.keyPinned = (pinnedKey != null);
                ClassicalHandshake.HandshakeOutcome outcome = ClassicalHandshake.clientHandshakeFull(
                        socketOut, socketIn, HandshakeConfig.hardened(), pinnedKey, List.of("CLASSICAL")
                );
                this.chosenSuite = outcome.chosenSuite();
                this.secureChannel = new ClassicalSecureChannel(
                        socketOut, socketIn, outcome.sessionKeys(), true, HandshakeConfig.hardened()
                );
            } else {
                // HYBRID: FIPS 204 ML-DSA-65 pinned key, FIPS 203 ML-KEM-768 + X25519
                PublicKey pinnedKey = explicitPinnedKey != null ? explicitPinnedKey : getOrLoadPinnedMlDsaKey();
                this.keyPinned = (pinnedKey != null);
                HybridHandshake.HandshakeOutcome outcome = HybridHandshake.clientHandshake(
                        socketOut, socketIn, pinnedKey, List.of("HYBRID", "CLASSICAL")
                );
                this.chosenSuite = outcome.chosenSuite();
                this.secureChannel = new ClassicalSecureChannel(
                        socketOut, socketIn, outcome.sessionKeys(), true, HandshakeConfig.safe()
                );
            }

            this.connectionStatus = "CONNECTED";
            this.connected.set(true);
            log.info("[CLIENT-ALICE] Handshake succeeded! Suite: {}, Key Pinned: {}", this.chosenSuite, this.keyPinned);
        } catch (Exception e) {
            this.connectionStatus = "FAILED";
            this.lastError = "Handshake failed"; // Generic external error, never internal secrets
            disconnect();
            log.warn("[CLIENT-ALICE] Handshake failed: {}", e.getMessage());
            throw new SecurityException("Handshake failed", e);
        } finally {
            HandshakeObserverContext.setGlobalObserver(HandshakeObserver.NOOP);
        }
    }

    public synchronized ChatMessageRecord sendMessage(String text) throws IOException, ClassNotFoundException {
        if (!connected.get() || secureChannel == null) {
            throw new IllegalStateException("Client is not connected to a secure session");
        }
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Message text cannot be empty");
        }

        long seq = secureChannel.getSendSeq();
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);

        secureChannel.send(payload);
        log.info("[CLIENT-ALICE] Sent message seq={} (\"{}\")", seq, text);

        // Receive ACK reply
        byte[] reply = secureChannel.receive();
        String replyText = new String(reply, StandardCharsets.UTF_8);
        log.info("[CLIENT-ALICE] Received reply: \"{}\"", replyText);

        String msgId = "alice-" + messageCounter.incrementAndGet();
        ChatMessageRecord record = new ChatMessageRecord(
                msgId, "Alice", text, seq, "SENT (Ack received: " + replyText + ")", null,
                null, Instant.now()
        );
        chatHistory.add(record);

        for (Consumer<ChatMessageRecord> listener : messageListeners) {
            try { listener.accept(record); } catch (Exception ignored) {}
        }
        return record;
    }

    public synchronized void disconnect() {
        connected.set(false);
        if (!"FAILED".equals(this.connectionStatus)) {
            this.connectionStatus = "DISCONNECTED";
        }
        if (secureChannel != null) {
            try { secureChannel.close(); } catch (Exception ignored) {}
            secureChannel = null;
        }
        if (clientSocket != null && !clientSocket.isClosed()) {
            try { clientSocket.close(); } catch (Exception ignored) {}
            clientSocket = null;
        }
        socketOut = null;
        socketIn = null;
    }

    public synchronized void reset() {
        this.connectionStatus = "DISCONNECTED";
        disconnect();
        chatHistory.clear();
        handshakeSteps.clear();
        chosenSuite = "NONE";
        keyPinned = false;
        lastError = null;
        messageCounter.set(0);
        log.info("[CLIENT-ALICE] Reset client state");
    }

    public String getConnectionStatus() {
        return connectionStatus;
    }

    public boolean isConnected() {
        return connected.get();
    }

    public String getChosenSuite() {
        return chosenSuite;
    }

    public boolean isKeyPinned() {
        return keyPinned;
    }

    public String getLastError() {
        return lastError;
    }

    public List<HandshakeStepRecord> getHandshakeSteps() {
        return Collections.unmodifiableList(handshakeSteps);
    }

    public List<ChatMessageRecord> getChatHistory() {
        return Collections.unmodifiableList(chatHistory);
    }

    public void addStepListener(Consumer<HandshakeStepRecord> listener) {
        stepListeners.add(listener);
    }

    public void addMessageListener(Consumer<ChatMessageRecord> listener) {
        messageListeners.add(listener);
    }

    public void setPinnedServerKeyMlDsa(PublicKey key) {
        this.pinnedServerKeyMlDsa = key;
    }

    public void setPinnedServerKeyRsa(PublicKey key) {
        this.pinnedServerKeyRsa = key;
    }

    private PublicKey getOrLoadPinnedMlDsaKey() {
        if (pinnedServerKeyMlDsa != null) return pinnedServerKeyMlDsa;
        loadPinnedKeysFromDisk();
        return pinnedServerKeyMlDsa;
    }

    private PublicKey getOrLoadPinnedRsaKey() {
        if (pinnedServerKeyRsa != null) return pinnedServerKeyRsa;
        loadPinnedKeysFromDisk();
        return pinnedServerKeyRsa;
    }

    private void loadPinnedKeysFromDisk() {
        try {
            Path keysDir = com.pqcaps.common.DataPaths.resolve("chat-lab/server-keys");
            Path mlDsaPath = keysDir.resolve("server_mldsa65.pub");
            if (Files.exists(mlDsaPath)) {
                byte[] encoded = Files.readAllBytes(mlDsaPath);
                this.pinnedServerKeyMlDsa = new MlDsaSignatureScheme().decodePublicKey(encoded);
            }
            Path rsaPath = keysDir.resolve("server_rsa.pub");
            if (Files.exists(rsaPath)) {
                byte[] encoded = Files.readAllBytes(rsaPath);
                this.pinnedServerKeyRsa = ClassicalCryptoSuite.getInstance().signatureScheme().decodePublicKey(encoded);
            }
        } catch (Exception e) {
            log.debug("[CLIENT-ALICE] Pinned keys not yet found on disk: {}", e.getMessage());
        }
    }
}
