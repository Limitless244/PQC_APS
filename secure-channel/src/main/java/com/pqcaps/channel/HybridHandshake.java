package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.X25519KeyExchange;
import com.pqcaps.common.*;
import com.pqcaps.common.KemKeyExchange.EncapsulationResult;
import com.pqcaps.kex.HybridKeyExchange;
import com.pqcaps.kex.HybridKeySchedule;
import com.pqcaps.kex.MlKemKeyExchange;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.List;

/**
 * Post-Quantum Hybrid TLS-style handshake implementing the complete 8-step protocol
 * with mutual key confirmation (Finished message exchange in both directions).
 */
public final class HybridHandshake {

    private static final int NONCE_LEN = 32;

    public static void setObserver(HandshakeObserver observer) {
        HandshakeObserverContext.setGlobalObserver(observer);
    }

    public record HandshakeOutcome(SessionKeys sessionKeys, String chosenSuite) {}

    private HybridHandshake() {}

    // ═══════════════════════════════════════════════════════════════
    // CLIENT SIDE
    // ═══════════════════════════════════════════════════════════════

    public static HandshakeOutcome clientHandshake(
            Socket socket,
            PublicKey pinnedServerKey,
            List<String> supportedSuites) throws IOException, ClassNotFoundException {
        return clientHandshake(socket, pinnedServerKey, supportedSuites, false);
    }

    public static HandshakeOutcome clientHandshake(
            Socket socket,
            PublicKey pinnedServerKey,
            List<String> supportedSuites,
            boolean allowInsecureNoPinning) throws IOException, ClassNotFoundException {
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.flush();
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        return clientHandshake(out, in, pinnedServerKey, supportedSuites, allowInsecureNoPinning);
    }

    public static HandshakeOutcome clientHandshake(
            ObjectOutputStream out,
            ObjectInputStream in,
            PublicKey pinnedServerKey,
            List<String> supportedSuites) throws IOException, ClassNotFoundException {
        return clientHandshake(out, in, pinnedServerKey, supportedSuites, false);
    }

    public static HandshakeOutcome clientHandshake(
            ObjectOutputStream out,
            ObjectInputStream in,
            PublicKey pinnedServerKey,
            List<String> supportedSuites,
            boolean allowInsecureNoPinning) throws IOException, ClassNotFoundException {

        if (supportedSuites == null || supportedSuites.isEmpty()) {
            supportedSuites = List.of("HYBRID", "PQ_ONLY");
        }

        SecureRandom rng = new SecureRandom();
        X25519KeyExchange xKex = new X25519KeyExchange();
        MlKemKeyExchange kKem = new MlKemKeyExchange();
        MlDsaSignatureScheme dsaAuth = new MlDsaSignatureScheme();

        // ── Step 1: Generate Ephemeral Keypairs ─────────────────────────────
        boolean needsClassical = supportedSuites.contains("HYBRID") || supportedSuites.contains("CLASSICAL");
        KeyPair xKp_c = needsClassical ? xKex.generateKeyPair() : null;
        KeyPair kKp_c = kKem.generateKeyPair();

        byte[] xpk_c = xKp_c != null ? xKp_c.getPublic().getEncoded() : null;
        byte[] kpk_c = kKp_c.getPublic().getEncoded();
        byte[] nonce_c = new byte[NONCE_LEN];
        rng.nextBytes(nonce_c);

        log("[CLIENT] [1/8] Generated ephemeral keypairs");
        if (xpk_c != null) {
            log("[CLIENT]       X25519 pk      : raw 32 B / DER %d B (raw: %s...)", xpk_c.length, rawX25519Hex(xpk_c));
        }
        log("[CLIENT]       ML-KEM-768 pk  : raw 1184 B / DER %d B (encoded: %s...)", kpk_c.length, hex4(kpk_c));
        log("[CLIENT]       Nonce_c        : %s...", hex4(nonce_c));

        // ── Step 2: Send ClientHello ───────────────────────────────────────
        ClientHello clientHello = new ClientHello(xpk_c, kpk_c, supportedSuites, nonce_c);
        out.writeObject(clientHello);
        out.flush();
        log("[CLIENT] [2/8] Sent ClientHello (suites=%s)", supportedSuites);
        int chWireBytes = (xpk_c != null) ? 1356 : 1311;
        HandshakeObserverContext.emit("ClientHello", "CLIENT_TO_SERVER", chWireBytes, hex4(kpk_c), "OK");

        // ── Step 4: Receive ServerHello ────────────────────────────────────
        ServerHello serverHello = (ServerHello) in.readObject();
        log("[CLIENT] [4/8] Received ServerHello (chosenSuite=%s)", serverHello.chosenSuite());
        if ("CLASSICAL".equalsIgnoreCase(serverHello.chosenSuite())) {
            log("[CLIENT]       ML-KEM ct      : none (suite CLASSICAL)");
        } else {
            log("[CLIENT]       ML-KEM ct      : 1088 B (%s...)", hex4(serverHello.ct()));
        }
        log("[CLIENT]       ML-DSA-65 sig  : %d B (%s...)",
                serverHello.signature() != null ? serverHello.signature().length : 0, hex4(serverHello.signature()));

        String chosenSuite = serverHello.chosenSuite();
        if (!supportedSuites.contains(chosenSuite)) {
            SecurityEventSink.emit("DOWNGRADE", "HIGH", "HybridHandshake", chosenSuite, "BLOCKED",
                    "Server chose unsupported cipher suite: " + chosenSuite);
            throw new SecurityException("handshake failed: Server chose unsupported cipher suite: " + chosenSuite);
        }

        // ── Step 5: Verify ML-DSA-65 Signature & Derive Keys ───────────────
        byte[] transcript = buildTranscript(
                clientHello.xpk_c(), clientHello.kpk_c(),
                serverHello.xpk_s(), serverHello.ct(),
                clientHello.suites(), serverHello.chosenSuite(),
                clientHello.nonce_c(), serverHello.nonce_s()
        );
        byte[] transcriptHash = sha256(transcript);

        if (pinnedServerKey != null) {
            boolean sigOk = dsaAuth.verify(pinnedServerKey, transcript, serverHello.signature());
            if (!sigOk) {
                log("[CLIENT] [ERROR] Server identity signature INVALID! Aborting.");
                SecurityEventSink.emit("MITM", "HIGH", "HybridHandshake", chosenSuite, "BLOCKED",
                        "Server identity signature verification failed! MITM detected.");
                SecurityEventSink.emit("DOWNGRADE", "HIGH", "HybridHandshake", chosenSuite, "BLOCKED",
                        "Downgrade attack detected: suite list in signed transcript was tampered");
                throw new SecurityException("handshake failed: Server identity signature verification failed! MITM detected.");
            }
            log("[CLIENT] [5/8] Verified server ML-DSA-65 signature [OK]");
            HandshakeObserverContext.emit("SignatureCheck", "CLIENT", 3309, hex4(serverHello.signature()), "OK");
        } else {
            if (!allowInsecureNoPinning) {
                log("[CLIENT] [ERROR] FAIL-CLOSED: No pinned server public key configured for %s! Aborting.", chosenSuite);
                SecurityEventSink.emit("MITM", "HIGH", "HybridHandshake", chosenSuite, "BLOCKED",
                        "FAIL-CLOSED: Pinned server public key is required for " + chosenSuite + ". Insecure operation without pinning is disabled.");
                throw new SecurityException(
                        "FAIL-CLOSED: Pinned server public key is required for " + chosenSuite +
                        ". Insecure operation without pinning is disabled by default.");
            }
            log("[CLIENT] [WARN] [INSECURE] allowInsecureNoPinning=true: Proceeding WITHOUT server identity verification!");
        }

        byte[] ss1 = null;
        if ("HYBRID".equalsIgnoreCase(chosenSuite) && serverHello.xpk_s() != null && xKp_c != null) {
            PublicKey xpk_s = xKex.decodePublicKey(serverHello.xpk_s());
            ss1 = xKex.deriveSharedSecret(xKp_c.getPrivate(), xpk_s);
            log("[CLIENT]       Derived ss1 (X25519)     : %s...", hex4(ss1));
        }

        byte[] ss2 = kKem.decapsulate(kKp_c.getPrivate(), serverHello.ct());
        log("[CLIENT]       Decapsulated ss2 (ML-KEM): %s...", hex4(ss2));

        SessionKeys sessionKeys = HybridKeySchedule.deriveSessionKeys(
                chosenSuite, ss1, ss2, clientHello.nonce_c(), serverHello.nonce_s(), transcriptHash);
        log("[CLIENT]       Derived session keys     : c2s=%s... s2c=%s... fin=%s...",
                hex4(sessionKeys.clientToServer()), hex4(sessionKeys.serverToClient()), hex4(sessionKeys.finishedKey()));

        if (ss1 != null) Arrays.fill(ss1, (byte) 0);
        Arrays.fill(ss2, (byte) 0);

        // ── Step 6: Send Client Finished Message ───────────────────────────
        byte[] finishedVerifyData = HybridKeySchedule.computeFinished(sessionKeys.finishedKey(), transcriptHash);
        FinishedMessage clientFinished = new FinishedMessage(finishedVerifyData);
        out.writeObject(clientFinished);
        out.flush();
        log("[CLIENT] [6/8] Sent Finished message (verifyData=%s...)", hex4(finishedVerifyData));
        HandshakeObserverContext.emit("ClientFinished", "CLIENT_TO_SERVER", 127, hex4(finishedVerifyData), "OK");

        // ── Step 7: Receive & Verify Server Finished (Mutual Confirmation) ──
        FinishedMessage serverFinished;
        try {
            serverFinished = (FinishedMessage) in.readObject();
        } catch (Exception e) {
            log("[CLIENT] [ERROR] Server aborted or connection lost before Finished confirmation");
            throw new SecurityException("handshake failed", e);
        }

        byte[] serverTranscriptHash = sha256(concat(transcriptHash, finishedVerifyData));
        boolean serverOk = HybridKeySchedule.verifyFinished(sessionKeys.finishedKey(), serverTranscriptHash, serverFinished.verifyData());
        if (!serverOk) {
            log("[CLIENT] [ERROR] Server Finished verification FAILED! Aborting.");
            SecurityEventSink.emit("TAMPER", "HIGH", "HybridHandshake", chosenSuite, "BLOCKED",
                    "Server Finished verification failed! Server key confirmation invalid.");
            throw new SecurityException("handshake failed");
        }
        log("[CLIENT] [7/8] Received & verified Server Finished (verifyData=%s...) [OK]", hex4(serverFinished.verifyData()));

        log("[CLIENT] [8/8] Handshake complete! Channel established.");
        HandshakeObserverContext.emit("ChannelEstablished", "BOTH", 0, "OK", "SECURE");
        return new HandshakeOutcome(sessionKeys, chosenSuite);
    }

    // ═══════════════════════════════════════════════════════════════
    // SERVER SIDE
    // ═══════════════════════════════════════════════════════════════

    public static HandshakeOutcome serverHandshake(
            Socket socket,
            PrivateKey serverSigningKey,
            boolean rejectClassical) throws IOException, ClassNotFoundException {
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.flush();
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        return serverHandshake(out, in, serverSigningKey, rejectClassical);
    }

    public static HandshakeOutcome serverHandshake(
            ObjectOutputStream out,
            ObjectInputStream in,
            PrivateKey serverSigningKey,
            boolean rejectClassical) throws IOException, ClassNotFoundException {

        SecureRandom rng = new SecureRandom();
        X25519KeyExchange xKex = new X25519KeyExchange();
        MlKemKeyExchange kKem = new MlKemKeyExchange();
        MlDsaSignatureScheme dsaAuth = new MlDsaSignatureScheme();

        // ── Receive ClientHello ────────────────────────────────────────────
        ClientHello clientHello = (ClientHello) in.readObject();
        log("[SERVER] [2/8] Received ClientHello from client (suites=%s)", clientHello.suites());

        // ── Step 3: Select Suite & Process KEX ──────────────────────────────
        String chosenSuite = selectSuite(clientHello.suites(), rejectClassical);
        log("[SERVER] [3/8] Selected suite: %s", chosenSuite);

        byte[] nonce_s = new byte[NONCE_LEN];
        rng.nextBytes(nonce_s);

        byte[] xpk_s = null;
        byte[] ss1 = null;
        if ("HYBRID".equalsIgnoreCase(chosenSuite) || "CLASSICAL".equalsIgnoreCase(chosenSuite)) {
            if (clientHello.xpk_c() == null) {
                throw new SecurityException("Client did not provide X25519 public key for " + chosenSuite);
            }
            KeyPair xKp_s = xKex.generateKeyPair();
            xpk_s = xKp_s.getPublic().getEncoded();
            PublicKey xpk_c = xKex.decodePublicKey(clientHello.xpk_c());
            ss1 = xKex.deriveSharedSecret(xKp_s.getPrivate(), xpk_c);
            log("[SERVER]       Computed ss1 (X25519)     : %s...", hex4(ss1));
        }

        byte[] ct = null;
        byte[] ss2 = null;
        if ("HYBRID".equalsIgnoreCase(chosenSuite) || "PQ_ONLY".equalsIgnoreCase(chosenSuite)) {
            if (clientHello.kpk_c() == null) {
                throw new SecurityException("Client did not provide ML-KEM public key for " + chosenSuite);
            }
            PublicKey kpk_c = kKem.decodePublicKey(clientHello.kpk_c());
            EncapsulationResult encResult = kKem.encapsulate(kpk_c);
            ct = encResult.ciphertext();
            ss2 = encResult.sharedSecret();
            log("[SERVER]       Encapsulated ss2 (ML-KEM) : %s... (ct=1088 B)", hex4(ss2));
        }

        byte[] transcript = buildTranscript(
                clientHello.xpk_c(), clientHello.kpk_c(),
                xpk_s, ct,
                clientHello.suites(), chosenSuite,
                clientHello.nonce_c(), nonce_s
        );
        byte[] transcriptHash = sha256(transcript);

        SessionKeys sessionKeys = HybridKeySchedule.deriveSessionKeys(
                chosenSuite, ss1, ss2, clientHello.nonce_c(), nonce_s, transcriptHash);
        log("[SERVER]       Derived session keys      : c2s=%s... s2c=%s... fin=%s...",
                hex4(sessionKeys.clientToServer()), hex4(sessionKeys.serverToClient()), hex4(sessionKeys.finishedKey()));

        if (ss1 != null) Arrays.fill(ss1, (byte) 0);
        if (ss2 != null) Arrays.fill(ss2, (byte) 0);

        byte[] signature = dsaAuth.sign(serverSigningKey, transcript);
        log("[SERVER]       ML-DSA-65 signature size : %d B (%s...)", signature.length, hex4(signature));

        // ── Step 4: Send ServerHello ───────────────────────────────────────
        ServerHello serverHello = new ServerHello(xpk_s, ct, chosenSuite, nonce_s, signature);
        out.writeObject(serverHello);
        out.flush();
        log("[SERVER] [4/8] Sent ServerHello to client");
        int shWireBytes = (xpk_s != null) ? 4488 : 4444;
        HandshakeObserverContext.emit("ServerHello", "SERVER_TO_CLIENT", shWireBytes, hex4(signature), "OK");

        // ── Step 6: Receive & Verify Client Finished ───────────────────────
        FinishedMessage clientFinished = (FinishedMessage) in.readObject();
        log("[SERVER] [6/8] Received Client Finished message (verifyData=%s...)", hex4(clientFinished.verifyData()));

        boolean finishedOk = HybridKeySchedule.verifyFinished(sessionKeys.finishedKey(), transcriptHash, clientFinished.verifyData());
        if (!finishedOk) {
            log("[SERVER] [ERROR] Finished verification FAILED! Possible ciphertext tampering or MITM.");
            SecurityEventSink.emit("TAMPER", "HIGH", "HybridHandshake", chosenSuite, "BLOCKED",
                    "Finished message verification failed! Transcript or KEM ciphertext was tampered.");
            throw new SecurityException("handshake failed: Finished message verification failed");
        }
        log("[SERVER]       Client Finished message verified [OK]");

        // ── Step 7: Send Server Finished (Mutual Confirmation) ─────────────
        byte[] serverTranscriptHash = sha256(concat(transcriptHash, clientFinished.verifyData()));
        byte[] serverVerifyData = HybridKeySchedule.computeFinished(sessionKeys.finishedKey(), serverTranscriptHash);
        FinishedMessage serverFinished = new FinishedMessage(serverVerifyData);
        out.writeObject(serverFinished);
        out.flush();
        log("[SERVER] [7/8] Sent Server Finished (verifyData=%s...)", hex4(serverVerifyData));
        HandshakeObserverContext.emit("ServerFinished", "SERVER_TO_CLIENT", 127, hex4(serverVerifyData), "OK");

        log("[SERVER] [8/8] Handshake complete! Channel established.");
        return new HandshakeOutcome(sessionKeys, chosenSuite);
    }

    private static String selectSuite(List<String> clientSuites, boolean rejectClassical) {
        if (clientSuites == null || clientSuites.isEmpty()) {
            throw new SecurityException("No cipher suites offered by client");
        }
        for (String suite : clientSuites) {
            if ("HYBRID".equalsIgnoreCase(suite)) {
                return "HYBRID";
            }
            if ("PQ_ONLY".equalsIgnoreCase(suite)) {
                return "PQ_ONLY";
            }
            if ("CLASSICAL".equalsIgnoreCase(suite)) {
                if (rejectClassical) {
                    continue;
                }
                return "CLASSICAL";
            }
        }
        SecurityEventSink.emit("DOWNGRADE", "HIGH", "HybridHandshake", "NONE", "BLOCKED",
                "No mutually acceptable cipher suite found (rejectClassical=" + rejectClassical + ")");
        throw new SecurityException("handshake failed: No mutually acceptable cipher suite found");
    }

    public static byte[] concat(byte[] a, byte[] b) {
        if (a == null) return b != null ? b.clone() : new byte[0];
        if (b == null) return a.clone();
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    public static byte[] buildTranscript(
            byte[] xpk_c, byte[] kpk_c,
            byte[] xpk_s, byte[] ct,
            List<String> suites, String chosenSuite,
            byte[] nonce_c, byte[] nonce_s) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            writeBytes(baos, xpk_c);
            writeBytes(baos, kpk_c);
            writeBytes(baos, xpk_s);
            writeBytes(baos, ct);
            writeString(baos, suites != null ? String.join(",", suites) : "");
            writeString(baos, chosenSuite != null ? chosenSuite : "");
            writeBytes(baos, nonce_c);
            writeBytes(baos, nonce_s);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return baos.toByteArray();
    }

    private static void writeBytes(ByteArrayOutputStream baos, byte[] b) throws IOException {
        if (b == null) {
            baos.write(new byte[]{0, 0, 0, 0});
        } else {
            baos.write((b.length >> 24) & 0xFF);
            baos.write((b.length >> 16) & 0xFF);
            baos.write((b.length >> 8) & 0xFF);
            baos.write(b.length & 0xFF);
            baos.write(b);
        }
    }

    private static void writeString(ByteArrayOutputStream baos, String s) throws IOException {
        writeBytes(baos, s != null ? s.getBytes(StandardCharsets.UTF_8) : null);
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String hex4(byte[] b) {
        return (b == null || b.length < 4) ? "null"
                : String.format("%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
    }

    public static String rawX25519Hex(byte[] xpk) {
        if (xpk == null) return "null";
        byte[] raw = xpk.length >= 32 ? Arrays.copyOfRange(xpk, xpk.length - 32, xpk.length) : xpk;
        return hex4(raw);
    }

    private static void log(String format, Object... args) {
        System.out.printf(format + "%n", args);
    }
}
