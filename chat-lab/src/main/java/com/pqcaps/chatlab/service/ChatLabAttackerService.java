package com.pqcaps.chatlab.service;

import com.pqcaps.chatlab.ChatMode;
import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.model.AttackerActionOutcome;
import com.pqcaps.chatlab.model.CapturedTrafficRecord;
import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.ClientHello;
import com.pqcaps.common.EncryptedRecord;
import com.pqcaps.common.FinishedMessage;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.ServerHello;
import com.pqcaps.common.SessionKeys;
import com.pqcaps.common.HandshakeObserverContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Mallory's Attacker TCP Proxy running on 127.0.0.1:9000, forwarding to 127.0.0.1:9001.
 * Intercepts, inspects, and manipulates real on-wire TCP traffic between Alice and Bob.
 */
@Service
public class ChatLabAttackerService {

    private static final Logger log = LoggerFactory.getLogger(ChatLabAttackerService.class);

    private final List<CapturedTrafficRecord> capturedTraffic = new CopyOnWriteArrayList<>();
    private final List<AttackerActionOutcome> actionLog = new CopyOnWriteArrayList<>();
    private final List<Consumer<CapturedTrafficRecord>> trafficListeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<AttackerActionOutcome>> actionListeners = new CopyOnWriteArrayList<>();

    private int listenPort;
    private int targetPort;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ServerSocket proxyServerSocket;
    private Thread listenerThread;

    // Controls
    private volatile boolean stripHybrid = false;
    private volatile boolean enableMitm = false;
    private volatile boolean dropNextRecord = false;
    private volatile boolean paused = false;

    // Last seen record & active connection
    private final AtomicReference<EncryptedRecord> lastCapturedRecord = new AtomicReference<>(null);
    private final AtomicReference<ObjectOutputStream> activeServerOut = new AtomicReference<>(null);
    private final AtomicReference<Socket> activeClientSocket = new AtomicReference<>(null);
    private final AtomicReference<Socket> activeServerSocket = new AtomicReference<>(null);
    private final AtomicLong recordCounter = new AtomicLong(0);

    // Attacker's own rogue identity keypair for MITM
    private final KeyPair attackerIdentityRsa;

    public ChatLabAttackerService(
            @Value("${attacker.tcp.listenPort:9000}") int listenPort,
            @Value("${attacker.tcp.targetPort:9001}") int targetPort) {
        this.listenPort = listenPort;
        this.targetPort = targetPort;
        this.attackerIdentityRsa = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();
    }

    public synchronized void start() throws IOException {
        start(this.listenPort, this.targetPort);
    }

    public synchronized void start(int listenPort, int targetPort) throws IOException {
        if (running.get()) {
            if (this.listenPort == listenPort && this.targetPort == targetPort) {
                return;
            }
            stop();
        }

        HostValidator.validateHost(HostValidator.LOCALHOST_IP);
        this.listenPort = listenPort;
        this.targetPort = targetPort;

        this.proxyServerSocket = new ServerSocket(listenPort, 50, InetAddress.getByName(HostValidator.LOCALHOST_IP));
        this.listenPort = this.proxyServerSocket.getLocalPort();
        this.running.set(true);

        log.info("[ATTACKER-MALLORY] Started TCP proxy on 127.0.0.1:{} -> target 127.0.0.1:{}",
                this.listenPort, this.targetPort);

        this.listenerThread = new Thread(this::listenLoop, "chat-lab-attacker-proxy");
        this.listenerThread.setDaemon(true);
        this.listenerThread.start();
    }

    public synchronized void stop() {
        running.set(false);
        if (proxyServerSocket != null && !proxyServerSocket.isClosed()) {
            try {
                proxyServerSocket.close();
            } catch (IOException ignored) {}
        }
        closeActiveSession();
        if (listenerThread != null) {
            listenerThread.interrupt();
        }
        log.info("[ATTACKER-MALLORY] Stopped TCP proxy");
    }

    public synchronized void reset() {
        closeActiveSession();
        capturedTraffic.clear();
        actionLog.clear();
        lastCapturedRecord.set(null);
        recordCounter.set(0);
        log.info("[ATTACKER-MALLORY] Reset captured traffic and action log");
    }

    public synchronized void setTargetPort(int targetPort) {
        this.targetPort = targetPort;
    }

    public synchronized void setListenPort(int listenPort) {
        this.listenPort = listenPort;
    }

    // ── Attack Control Toggles ─────────────────────────────────────────────

    public void setStripHybrid(boolean enable) {
        this.stripHybrid = enable;
        recordAction("STRIP_HYBRID", enable ? "ENABLED" : "DISABLED",
                "Strip HYBRID suite from ClientHello is now " + (enable ? "ON (downgrade attack active)" : "OFF"));
    }

    public boolean isStripHybrid() {
        return stripHybrid;
    }

    public void setEnableMitm(boolean enable) {
        this.enableMitm = enable;
        recordAction("ENABLE_MITM", enable ? "ENABLED" : "DISABLED",
                "Two-leg MITM proxy mode is now " + (enable ? "ON (rogue RSA key termination active)" : "OFF"));
    }

    public boolean isEnableMitm() {
        return enableMitm;
    }

    public void setDropNextRecord(boolean drop) {
        this.dropNextRecord = drop;
        recordAction("DROP_RECORD", drop ? "ARMED" : "DISARMED",
                "Drop next record is " + (drop ? "ARMED (next record will be dropped)" : "OFF"));
    }

    public boolean isDropNextRecord() {
        return dropNextRecord;
    }

    public void setPaused(boolean pause) {
        this.paused = pause;
        recordAction("PAUSE", pause ? "PAUSED" : "RESUMED",
                "Traffic forwarding is " + (pause ? "PAUSED" : "RESUMED"));
    }

    public boolean isPaused() {
        return paused;
    }

    // ── Interactive Actions ────────────────────────────────────────────────

    public AttackerActionOutcome replayLastRecord() {
        EncryptedRecord record = lastCapturedRecord.get();
        ObjectOutputStream out = activeServerOut.get();

        if (record == null) {
            AttackerActionOutcome outcome = recordAction("REPLAY", "FAILED", "No previous record available to replay");
            return outcome;
        }
        if (out == null) {
            AttackerActionOutcome outcome = recordAction("REPLAY", "FAILED", "No active TCP connection to server");
            return outcome;
        }

        try {
            out.writeObject(record);
            out.flush();
            String detail = "Forwarded duplicate record (seq=" + record.sequenceNumber() + ", ct=" + hex4(record.ciphertext()) + ") to server";
            AttackerActionOutcome outcome = recordAction("REPLAY", "FORWARDED", detail);
            log.info("[ATTACKER-MALLORY] Replayed record seq={} to server", record.sequenceNumber());
            return outcome;
        } catch (IOException e) {
            return recordAction("REPLAY", "ERROR", "Failed to send replayed record: " + e.getMessage());
        }
    }

    public AttackerActionOutcome flipBit() {
        EncryptedRecord record = lastCapturedRecord.get();
        ObjectOutputStream out = activeServerOut.get();

        if (record == null) {
            return recordAction("TAMPER", "FAILED", "No previous record available to tamper");
        }
        if (out == null) {
            return recordAction("TAMPER", "FAILED", "No active TCP connection to server");
        }

        try {
            byte[] tamperedCt = record.ciphertext().clone();
            tamperedCt[0] ^= 0x01; // Invert first bit

            // Set seq to record.sequenceNumber() + 1 so sequence check passes and TamperGuard catches the tag failure
            long targetSeq = record.sequenceNumber() + 1;
            EncryptedRecord tamperedRecord = new EncryptedRecord(targetSeq, record.nonce(), tamperedCt);
            out.writeObject(tamperedRecord);
            out.flush();

            String detail = "Forwarded bit-flipped record (seq=" + targetSeq + ", modified ct=" + hex4(tamperedCt) + ") to server";
            AttackerActionOutcome outcome = recordAction("TAMPER", "FORWARDED", detail);
            log.info("[ATTACKER-MALLORY] Sent bit-flipped record seq={} to server", targetSeq);
            return outcome;
        } catch (IOException e) {
            return recordAction("TAMPER", "ERROR", "Failed to send tampered record: " + e.getMessage());
        }
    }

    public List<CapturedTrafficRecord> getCapturedTraffic() {
        return Collections.unmodifiableList(capturedTraffic);
    }

    public List<AttackerActionOutcome> getActionLog() {
        return Collections.unmodifiableList(actionLog);
    }

    public int getListenPort() {
        return listenPort;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public boolean isRunning() {
        return running.get();
    }

    public void addTrafficListener(Consumer<CapturedTrafficRecord> listener) {
        trafficListeners.add(listener);
    }

    public void addActionListener(Consumer<AttackerActionOutcome> listener) {
        actionListeners.add(listener);
    }

    // ── Proxy Socket Loop ──────────────────────────────────────────────────

    private void listenLoop() {
        while (running.get() && !proxyServerSocket.isClosed()) {
            try {
                Socket clientSocket = proxyServerSocket.accept();
                HostValidator.validateHost(clientSocket.getInetAddress().getHostAddress());
                Thread worker = new Thread(() -> handleProxyConnection(clientSocket), "chat-lab-proxy-worker");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                if (!running.get()) break;
            }
        }
    }

    private void handleProxyConnection(Socket clientSocket) {
        log.info("[ATTACKER-MALLORY] Accepted connection from Client {}", clientSocket.getRemoteSocketAddress());
        activeClientSocket.set(clientSocket);

        if (this.enableMitm) {
            runTwoLegMitmProxy(clientSocket);
        } else {
            runTransparentInspectionProxy(clientSocket);
        }
    }

    /**
     * Case A: Two-leg MITM Proxy (exploits VULN-4).
     * Decrypts, inspects plaintext, and re-encrypts in CLASSICAL-VULNERABLE mode.
     * In HARDENED/HYBRID mode, client rejects attacker's untrusted key and aborts.
     */
    private void runTwoLegMitmProxy(Socket clientSocket) {
        Socket serverSocket = null;
        try {
            HostValidator.validateHost(HostValidator.LOCALHOST_IP);
            serverSocket = new Socket(HostValidator.LOCALHOST_IP, this.targetPort);
            activeServerSocket.set(serverSocket);

            recordAction("MITM", "INITIATED", "Conducting two handshakes: fake server with Client, fake client with Server");

            ObjectInputStream cIn = new ObjectInputStream(clientSocket.getInputStream());
            ObjectOutputStream cOut = new ObjectOutputStream(clientSocket.getOutputStream());
            cOut.flush();

            // Leg 1: Handshake with Client using attacker's rogue RSA keypair (labeled [MALLORY-ROGUE-SERVER])
            SessionKeys keysClientProxy;
            try {
                ClassicalHandshake.HandshakeOutcome outcomeCP = rogueServerHandshake(
                        cIn, cOut, attackerIdentityRsa);
                keysClientProxy = outcomeCP.sessionKeys();
            } catch (Exception e) {
                recordTraffic("CLIENT_TO_SERVER", 0, "none", null,
                        "[MITM BLOCKED]: Client refused untrusted attacker key (key pinning active)", "BLOCKED");
                recordAction("MITM", "BLOCKED", "Client rejected attacker's RSA key (pinned key check prevented MITM)");
                return;
            }

            ObjectOutputStream sOut = new ObjectOutputStream(serverSocket.getOutputStream());
            sOut.flush();
            ObjectInputStream sIn = new ObjectInputStream(serverSocket.getInputStream());

            // Leg 2: Handshake with real Server as a client
            ClassicalHandshake.HandshakeOutcome outcomePS = ClassicalHandshake.clientHandshakeFull(
                    sOut, sIn, HandshakeConfig.vulnerable(), null, List.of("CLASSICAL"));
            SessionKeys keysProxyServer = outcomePS.sessionKeys();

            recordAction("MITM", "SUCCEEDED", "Both handshakes established! Plaintext interception active in vulnerable mode.");

            // Open secure channels on both legs using existing streams
            try (ClassicalSecureChannel channelCP = new ClassicalSecureChannel(cOut, cIn, keysClientProxy, false, HandshakeConfig.vulnerable());
                 ClassicalSecureChannel channelPS = new ClassicalSecureChannel(sOut, sIn, keysProxyServer, true, HandshakeConfig.vulnerable())) {

                while (running.get() && !clientSocket.isClosed() && !serverSocket.isClosed()) {
                    byte[] clientPayload;
                    try {
                        clientPayload = channelCP.receive();
                    } catch (Exception e) {
                        break;
                    }

                    String plaintextC2S = new String(clientPayload, StandardCharsets.UTF_8);
                    log.info("[ATTACKER-MALLORY] [MITM INTERCEPTED C2S]: \"{}\"", plaintextC2S);

                    recordTraffic("CLIENT_TO_SERVER", clientPayload.length, hex4(keysClientProxy.clientToServer()),
                            channelCP.getRecvSeq() - 1,
                            "[MITM Intercepted Plaintext]: \"" + plaintextC2S + "\"", "DECRYPTED");

                    // Forward to Server
                    channelPS.send(clientPayload);

                    // Receive Server reply
                    byte[] serverPayload;
                    try {
                        serverPayload = channelPS.receive();
                    } catch (Exception e) {
                        break;
                    }

                    String plaintextS2C = new String(serverPayload, StandardCharsets.UTF_8);
                    log.info("[ATTACKER-MALLORY] [MITM INTERCEPTED S2C]: \"{}\"", plaintextS2C);

                    recordTraffic("SERVER_TO_CLIENT", serverPayload.length, hex4(keysProxyServer.serverToClient()),
                            channelPS.getRecvSeq() - 1,
                            "[MITM Intercepted Plaintext]: \"" + plaintextS2C + "\"", "DECRYPTED");

                    // Forward reply to Client
                    channelCP.send(serverPayload);
                }
            }
        } catch (Exception e) {
            log.warn("[ATTACKER-MALLORY] MITM proxy session ended: {}", e.getMessage());
            recordAction("MITM", "ENDED", "MITM session ended: " + e.getMessage());
        } finally {
            closeActiveSession();
        }
    }

    /**
     * Executes Leg 1 of MITM handshake posing as a rogue server to Alice.
     * All log messages are explicitly labeled [MALLORY-ROGUE-SERVER] (not [SERVER]).
     */
    private ClassicalHandshake.HandshakeOutcome rogueServerHandshake(
            ObjectInputStream in, ObjectOutputStream out, KeyPair rogueIdentity)
            throws Exception {
        ClassicalCryptoSuite suite = ClassicalCryptoSuite.getInstance();
        SecureRandom rng = new SecureRandom();

        // ── Step 1: read ClientHello ──────────────────────────────────────────
        ClientHello hello = (ClientHello) in.readObject();
        String line1 = String.format("[MALLORY-ROGUE-SERVER] [1/4] Got  ClientHello  xpk_c=%s...  suites=%s",
                hex4(hello.xpk_c()), hello.suites());
        System.out.println(line1);
        log.info(line1);

        // ── Step 2: generate ephemeral keypair + DH ───────────────────────────
        KeyPair xKp = suite.keyExchange().generateKeyPair();
        byte[] xpk_s = xKp.getPublic().getEncoded();
        PublicKey peerPk = suite.keyExchange().decodePublicKey(hello.xpk_c());
        byte[] ss = suite.keyExchange().deriveSharedSecret(xKp.getPrivate(), peerPk);
        String line2 = String.format("[MALLORY-ROGUE-SERVER] [2/4] X25519 DH done   xpk_s=%s...  ss=%s...",
                hex4(xpk_s), hex4(ss));
        System.out.println(line2);
        log.info(line2);

        // ── Step 3: sign transcript with rogue key and send ServerHello ───────
        byte[] nonce_s = new byte[32];
        rng.nextBytes(nonce_s);

        String chosenSuite = hello.suites().contains("CLASSICAL") ? "CLASSICAL"
                : (hello.suites().isEmpty() ? "CLASSICAL" : hello.suites().get(0));

        ServerHello partial = new ServerHello(xpk_s, chosenSuite, nonce_s, new byte[0]);
        byte[] transcript = ClassicalHandshake.buildTranscript(hello, partial, HandshakeConfig.vulnerable());

        String line3a = "[MALLORY-ROGUE-SERVER] [3/4] [VULN-1] Suite list NOT included in signature [WARN]";
        System.out.println(line3a);
        log.info(line3a);

        byte[] sig = suite.signatureScheme().sign(rogueIdentity.getPrivate(), transcript);
        ServerHello sh = new ServerHello(xpk_s, chosenSuite, nonce_s, sig);
        out.writeObject(sh);
        out.flush();
        String line3b = String.format("[MALLORY-ROGUE-SERVER] [3/4] Sent ServerHello  suite=%s  nonce_s=%s...  sig=%s...",
                chosenSuite, hex4(nonce_s), hex4(sig));
        System.out.println(line3b);
        log.info(line3b);
        HandshakeObserverContext.emit("ServerHello", "SERVER_TO_CLIENT", 390, hex4(xpk_s), "OK");

        // ── Step 4: derive session keys ───────────────────────────────────────
        SessionKeys keys = ClassicalHandshake.deriveSessionKeys(ss, hello.nonce_c(), nonce_s);
        Arrays.fill(ss, (byte) 0);
        String line4 = String.format("[MALLORY-ROGUE-SERVER] [4/4] Session keys derived  s2c=%s...  Handshake complete OK",
                hex4(keys.serverToClient()));
        System.out.println(line4);
        log.info(line4);

        return new ClassicalHandshake.HandshakeOutcome(keys, chosenSuite);
    }

    /**
     * Case B: Transparent Inspection & Active Record Modification Proxy.
     */
    private void runTransparentInspectionProxy(Socket clientSocket) {
        Socket serverSocket = null;
        ObjectOutputStream serverOut = null;
        ObjectInputStream serverIn = null;
        ObjectInputStream clientIn = null;
        ObjectOutputStream clientOut = null;

        try {
            HostValidator.validateHost(HostValidator.LOCALHOST_IP);
            serverSocket = new Socket(HostValidator.LOCALHOST_IP, this.targetPort);
            activeServerSocket.set(serverSocket);

            serverOut = new ObjectOutputStream(serverSocket.getOutputStream());
            serverOut.flush();
            serverIn = new ObjectInputStream(serverSocket.getInputStream());

            clientIn = new ObjectInputStream(clientSocket.getInputStream());
            clientOut = new ObjectOutputStream(clientSocket.getOutputStream());
            clientOut.flush();

            activeServerOut.set(serverOut);

            final ObjectInputStream sIn = serverIn;
            final ObjectOutputStream cOut = clientOut;
            final Socket sSocket = serverSocket;
            final Socket cSocket = clientSocket;

            // Background worker for Server -> Client forwarding
            Thread s2cThread = new Thread(() -> {
                try {
                    while (running.get() && !sSocket.isClosed() && !cSocket.isClosed()) {
                        Object obj;
                        try {
                            obj = sIn.readObject();
                        } catch (EOFException | java.net.SocketException e) {
                            break;
                        }

                        if (obj instanceof ServerHello sh) {
                            cOut.writeObject(sh);
                            cOut.flush();
                            recordTraffic("SERVER_TO_CLIENT", sh.signature() != null ? sh.signature().length : 0,
                                    hex4(sh.signature()), null,
                                    "ServerHello (chosenSuite=" + sh.chosenSuite() + ")", "FORWARDED");
                        } else if (obj instanceof FinishedMessage fm) {
                            cOut.writeObject(fm);
                            cOut.flush();
                            recordTraffic("SERVER_TO_CLIENT", fm.verifyData() != null ? fm.verifyData().length : 0,
                                    hex4(fm.verifyData()), null,
                                    "ServerFinished (verifyData=" + hex4(fm.verifyData()) + "...)", "FORWARDED");
                        } else if (obj instanceof EncryptedRecord record) {
                            cOut.writeObject(record);
                            cOut.flush();
                            recordTraffic("SERVER_TO_CLIENT", record.ciphertext().length, hex4(record.ciphertext()),
                                    record.sequenceNumber(),
                                    "[Encrypted Reply seq=" + record.sequenceNumber() + "]: " + hex4(record.ciphertext()) + "... (" + record.ciphertext().length + " B)", "FORWARDED");
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    closeActiveSession();
                }
            }, "chat-lab-proxy-s2c");
            s2cThread.setDaemon(true);
            s2cThread.start();

            // Client -> Server forwarding loop
            while (running.get() && !clientSocket.isClosed() && !serverSocket.isClosed()) {
                Object obj;
                try {
                    obj = clientIn.readObject();
                } catch (EOFException | java.net.SocketException e) {
                    break;
                }

                // Pause check
                while (paused && running.get()) {
                    Thread.sleep(50);
                }

                if (obj instanceof ClientHello origHello) {
                    if (this.stripHybrid) {
                        // DOWNGRADE ATTACK (VULN-1)
                        List<String> downgraded = new ArrayList<>(origHello.suites());
                        downgraded.remove("HYBRID");
                        downgraded.remove("PQ_ONLY");
                        if (downgraded.isEmpty()) {
                            downgraded.add("CLASSICAL");
                        }

                        ClientHello modifiedHello = new ClientHello(origHello.xpk_c(), origHello.kpk_c(), downgraded, origHello.nonce_c());
                        serverOut.writeObject(modifiedHello);
                        serverOut.flush();

                        String detail = "BEFORE: " + origHello.suites() + " AFTER: " + downgraded + " Handshake accepted: true";
                        recordTraffic("CLIENT_TO_SERVER", 111, hex4(origHello.xpk_c()), null,
                                "[DOWNGRADE ATTACK] " + detail, "TAMPERED");
                        recordAction("STRIP_HYBRID", "TAMPERED", detail);
                        log.info("[ATTACKER-MALLORY] Downgrade executed: {}", detail);
                    } else {
                        serverOut.writeObject(origHello);
                        serverOut.flush();
                        recordTraffic("CLIENT_TO_SERVER", origHello.xpk_c() != null ? 1356 : 1311,
                                hex4(origHello.xpk_c()), null,
                                "ClientHello (suites=" + origHello.suites() + ")", "FORWARDED");
                    }
                } else if (obj instanceof FinishedMessage fm) {
                    serverOut.writeObject(fm);
                    serverOut.flush();
                    recordTraffic("CLIENT_TO_SERVER", fm.verifyData() != null ? fm.verifyData().length : 0,
                            hex4(fm.verifyData()), null,
                            "ClientFinished (verifyData=" + hex4(fm.verifyData()) + "...)", "FORWARDED");
                } else if (obj instanceof EncryptedRecord record) {
                    lastCapturedRecord.set(record);

                    if (dropNextRecord) {
                        dropNextRecord = false;
                        recordTraffic("CLIENT_TO_SERVER", record.ciphertext().length, hex4(record.ciphertext()),
                                record.sequenceNumber(),
                                "[DROPPED] Record seq=" + record.sequenceNumber() + " dropped by attacker proxy", "DROPPED");
                        recordAction("DROP", "DROPPED", "Dropped record seq=" + record.sequenceNumber());
                        log.info("[ATTACKER-MALLORY] Dropped record seq={}", record.sequenceNumber());
                        continue;
                    }

                    serverOut.writeObject(record);
                    serverOut.flush();

                    recordTraffic("CLIENT_TO_SERVER", record.ciphertext().length, hex4(record.ciphertext()),
                            record.sequenceNumber(),
                            "[Encrypted Record seq=" + record.sequenceNumber() + "]: " + hex4(record.ciphertext()) + "... (" + record.ciphertext().length + " B ciphertext)", "FORWARDED");
                }
            }
        } catch (Exception e) {
            log.warn("[ATTACKER-MALLORY] Transparent proxy session ended: {}", e.getMessage());
        } finally {
            closeActiveSession();
        }
    }

    private void closeActiveSession() {
        activeServerOut.set(null);
        Socket cSock = activeClientSocket.getAndSet(null);
        if (cSock != null && !cSock.isClosed()) {
            try { cSock.close(); } catch (IOException ignored) {}
        }
        Socket sSock = activeServerSocket.getAndSet(null);
        if (sSock != null && !sSock.isClosed()) {
            try { sSock.close(); } catch (IOException ignored) {}
        }
    }

    private void recordTraffic(String dir, int len, String hex4, Long seq, String view, String status) {
        String id = "traf-" + recordCounter.incrementAndGet();
        CapturedTrafficRecord rec = new CapturedTrafficRecord(
                id, dir, len, hex4, seq, view, status, Instant.now()
        );
        capturedTraffic.add(rec);
        for (Consumer<CapturedTrafficRecord> listener : trafficListeners) {
            try { listener.accept(rec); } catch (Exception ignored) {}
        }
    }

    private AttackerActionOutcome recordAction(String action, String status, String detail) {
        AttackerActionOutcome outcome = new AttackerActionOutcome(action, status, detail, Instant.now());
        actionLog.add(outcome);
        for (Consumer<AttackerActionOutcome> listener : actionListeners) {
            try { listener.accept(outcome); } catch (Exception ignored) {}
        }
        return outcome;
    }

    private static String hex4(byte[] b) {
        if (b == null || b.length < 4) return "null";
        return String.format("%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    }
}
