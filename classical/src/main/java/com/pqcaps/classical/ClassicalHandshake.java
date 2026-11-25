package com.pqcaps.classical;

import com.pqcaps.common.*;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.List;

/**
 * Classical (Phase 1) TLS-style handshake over a TCP socket.
 */
public final class ClassicalHandshake {

    /** Nonce size in bytes. */
    private static final int NONCE_LEN = 32;
    /** Session key size in bytes (AES-256). */
    private static final int KEY_LEN = 32;

    static final byte[] INFO_C2S = "pqcaps-classical-c2s".getBytes(StandardCharsets.UTF_8);
    static final byte[] INFO_S2C = "pqcaps-classical-s2c".getBytes(StandardCharsets.UTF_8);

    private ClassicalHandshake() {}

    public static void setObserver(HandshakeObserver observer) {
        HandshakeObserverContext.setGlobalObserver(observer);
    }

    public record HandshakeOutcome(SessionKeys sessionKeys, String chosenSuite) {}

    // ═══════════════════════════════════════════════════════════════
    // CLIENT SIDE
    // ═══════════════════════════════════════════════════════════════

    public static SessionKeys clientHandshake(Socket socket, HandshakeConfig config,
                                               PublicKey pinnedServerKey) throws IOException, ClassNotFoundException {
        return clientHandshake(socket, config, pinnedServerKey, List.of("CLASSICAL"));
    }

    public static SessionKeys clientHandshake(Socket socket, HandshakeConfig config,
                                               PublicKey pinnedServerKey, List<String> suites) throws IOException, ClassNotFoundException {
        return clientHandshakeFull(socket, config, pinnedServerKey, suites).sessionKeys();
    }

    public static HandshakeOutcome clientHandshakeFull(Socket socket, HandshakeConfig config,
                                                        PublicKey pinnedServerKey, List<String> suites) throws IOException, ClassNotFoundException {
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.flush();
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        return clientHandshakeFull(out, in, config, pinnedServerKey, suites);
    }

    public static HandshakeOutcome clientHandshakeFull(ObjectOutputStream out, ObjectInputStream in, HandshakeConfig config,
                                                        PublicKey pinnedServerKey, List<String> suites) throws IOException, ClassNotFoundException {
        ClassicalCryptoSuite suite = ClassicalCryptoSuite.getInstance();
        SecureRandom rng = new SecureRandom();

        // ── Step 1: generate ephemeral X25519 keypair ─────────────────────────
        KeyPair xKp = suite.keyExchange().generateKeyPair();
        byte[] xpk_c = xKp.getPublic().getEncoded();
        log("[CLIENT] [1/5] X25519 keypair  xpk_c=%s...", hex4(xpk_c));

        // ── Step 2: build and send ClientHello ───────────────────────────────
        byte[] nonce_c = new byte[NONCE_LEN];
        rng.nextBytes(nonce_c);
        List<String> offeredSuites = (suites != null && !suites.isEmpty()) ? suites : List.of("CLASSICAL");
        ClientHello hello = new ClientHello(xpk_c, offeredSuites, nonce_c);
        HandshakeObserverContext.emit("ClientHello", "CLIENT_TO_SERVER", 111, hex4(xpk_c), "OK");
        out.writeObject(hello);
        out.flush();
        log("[CLIENT] [2/5] Sent ClientHello  nonce_c=%s...  suites=%s", hex4(nonce_c), offeredSuites);

        // ── Step 3: receive ServerHello ───────────────────────────────────────
        ServerHello sh = (ServerHello) in.readObject();
        log("[CLIENT] [3/5] Got  ServerHello  xpk_s=%s...  suite=%s  nonce_s=%s...",
                hex4(sh.xpk_s()), sh.chosenSuite(), hex4(sh.nonce_s()));

        // ── Step 4: verify server signature ───────────────────────────────────
        if (config.isSkipKeyPinning()) {
            log("[CLIENT] [4/5] [VULN-4] Skipping server key pinning [WARN]");
        } else {
            byte[] transcript = buildTranscript(hello, sh, config);
            boolean ok = suite.signatureScheme().verify(pinnedServerKey, transcript, sh.signature());
            if (!ok) {
                log("[CLIENT] [ERROR] Server identity signature INVALID! Aborting.");
                // If suite signature was enabled, signature failure might be downgrade or MITM
                if (!config.isSkipSuiteSignature()) {
                    SecurityEventSink.emit("DOWNGRADE", "HIGH", "ClassicalHandshake", sh.chosenSuite(), "BLOCKED",
                            "Server signature verification FAILED -- suite list in signed transcript was tampered");
                }
                SecurityEventSink.emit("MITM", "HIGH", "ClassicalHandshake", sh.chosenSuite(), "BLOCKED",
                        "Server signature verification FAILED -- possible MITM attack!");
                throw new SecurityException("Server signature verification FAILED -- possible MITM attack!");
            }
            log("[CLIENT] [4/5] Server signature verified OK");
            HandshakeObserverContext.emit("SignatureCheck", "CLIENT", 256, hex4(sh.signature()), "OK");
        }

        // ── Step 5: derive session keys ───────────────────────────────────────
        PublicKey xpk_s = suite.keyExchange().decodePublicKey(sh.xpk_s());
        byte[] ss = suite.keyExchange().deriveSharedSecret(xKp.getPrivate(), xpk_s);
        SessionKeys keys = deriveSessionKeys(ss, nonce_c, sh.nonce_s());
        Arrays.fill(ss, (byte) 0);
        log("[CLIENT] [5/5] Session keys derived  c2s=%s...  Handshake complete OK", hex4(keys.clientToServer()));
        HandshakeObserverContext.emit("ChannelEstablished", "BOTH", 0, "OK", "SECURE");

        return new HandshakeOutcome(keys, sh.chosenSuite());
    }

    // ═══════════════════════════════════════════════════════════════
    // SERVER SIDE
    // ═══════════════════════════════════════════════════════════════

    public static SessionKeys serverHandshake(Socket socket, HandshakeConfig config,
                                               KeyPair serverIdentity) throws IOException, ClassNotFoundException {
        return serverHandshakeFull(socket, config, serverIdentity).sessionKeys();
    }

    public static HandshakeOutcome serverHandshakeFull(Socket socket, HandshakeConfig config,
                                                       KeyPair serverIdentity) throws IOException, ClassNotFoundException {
        ObjectInputStream in   = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.flush();
        return serverHandshakeFull(in, out, config, serverIdentity);
    }

    public static HandshakeOutcome serverHandshakeFull(ObjectInputStream in, ObjectOutputStream out, HandshakeConfig config,
                                                       KeyPair serverIdentity) throws IOException, ClassNotFoundException {
        ClassicalCryptoSuite suite = ClassicalCryptoSuite.getInstance();
        SecureRandom rng = new SecureRandom();

        // ── Step 1: receive ClientHello ───────────────────────────────────────
        ClientHello hello = (ClientHello) in.readObject();
        log("[SERVER] [1/4] Got  ClientHello  xpk_c=%s...  suites=%s",
                hex4(hello.xpk_c()), hello.suites());

        // ── Step 2: generate ephemeral server keypair + compute shared secret ─
        KeyPair xKp = suite.keyExchange().generateKeyPair();
        byte[] xpk_s = xKp.getPublic().getEncoded();
        PublicKey peerPk = suite.keyExchange().decodePublicKey(hello.xpk_c());
        byte[] ss = suite.keyExchange().deriveSharedSecret(xKp.getPrivate(), peerPk);
        log("[SERVER] [2/4] X25519 DH done   xpk_s=%s...  ss=%s...", hex4(xpk_s), hex4(ss));

        // ── Step 3: sign transcript and send ServerHello ──────────────────────
        byte[] nonce_s = new byte[NONCE_LEN];
        rng.nextBytes(nonce_s);

        String chosenSuite = hello.suites().contains("CLASSICAL") ? "CLASSICAL"
                : (hello.suites().contains("CLASSICAL_WEAK") ? "CLASSICAL_WEAK"
                : (hello.suites().isEmpty() ? "CLASSICAL" : hello.suites().get(0)));

        ServerHello partial = new ServerHello(xpk_s, chosenSuite, nonce_s, new byte[0]);
        byte[] transcript = buildTranscript(hello, partial, config);

        if (config.isSkipSuiteSignature()) {
            log("[SERVER] [3/4] [VULN-1] Suite list NOT included in signature [WARN]");
        }

        byte[] sig = suite.signatureScheme().sign(serverIdentity.getPrivate(), transcript);
        ServerHello sh = new ServerHello(xpk_s, chosenSuite, nonce_s, sig);
        HandshakeObserverContext.emit("ServerHello", "SERVER_TO_CLIENT", 390, hex4(xpk_s), "OK");
        out.writeObject(sh);
        out.flush();
        log("[SERVER] [3/4] Sent ServerHello  suite=%s  nonce_s=%s...  sig=%s...", chosenSuite, hex4(nonce_s), hex4(sig));

        // ── Step 4: derive session keys ───────────────────────────────────────
        SessionKeys keys = deriveSessionKeys(ss, hello.nonce_c(), nonce_s);
        Arrays.fill(ss, (byte) 0);
        log("[SERVER] [4/4] Session keys derived  s2c=%s...  Handshake complete OK", hex4(keys.serverToClient()));

        return new HandshakeOutcome(keys, chosenSuite);
    }

    public static byte[] buildTranscript(ClientHello hello, ServerHello sh, HandshakeConfig config) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            if (!config.isSkipSuiteSignature()) {
                for (String s : hello.suites()) {
                    buf.write(s.getBytes(StandardCharsets.UTF_8));
                    buf.write(0x00);
                }
            }
            buf.write(hello.xpk_c());
            buf.write(sh.xpk_s());
            buf.write(hello.nonce_c());
            buf.write(sh.nonce_s());
        } catch (IOException e) {
            throw new IllegalStateException("Cannot build transcript", e);
        }
        return buf.toByteArray();
    }

    public static SessionKeys deriveSessionKeys(byte[] ss, byte[] nonce_c, byte[] nonce_s) {
        byte[] salt = HkdfSha256.concat(nonce_c, nonce_s);
        byte[] c2s  = HkdfSha256.deriveKey(ss, salt, INFO_C2S, KEY_LEN);
        byte[] s2c  = HkdfSha256.deriveKey(ss, salt, INFO_S2C, KEY_LEN);
        return new SessionKeys(c2s, s2c);
    }

    private static void log(String fmt, Object... args) {
        System.out.printf(fmt + "%n", args);
    }

    public static String hex4(byte[] b) {
        if (b == null || b.length < 4) return "(null)";
        int offset = (b.length == 44 && b[0] == (byte) 0x30 && b[1] == (byte) 0x2a) ? 12 : 0;
        return String.format("%02x%02x%02x%02x", b[offset], b[offset + 1], b[offset + 2], b[offset + 3]);
    }
}
