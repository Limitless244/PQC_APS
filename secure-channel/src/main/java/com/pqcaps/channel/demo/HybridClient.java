package com.pqcaps.channel.demo;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.channel.HybridHandshake;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.List;

/**
 * Post-Quantum & Hybrid secure channel TCP Client demo.
 *
 * <p>Supports {@code --suite HYBRID|PQ_ONLY|CLASSICAL} (default: HYBRID).
 */
public final class HybridClient {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 9000;
    private static final Path PINNED_KEY_PATH = Path.of("server_identity_mldsa65.key");

    public static void main(String[] args) throws Exception {
        String host = DEFAULT_HOST;
        int port = DEFAULT_PORT;
        String suiteArg = "HYBRID";

        for (int i = 0; i < args.length; i++) {
            if ("--suite".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                suiteArg = args[++i].toUpperCase();
            } else if ("--host".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                host = args[++i];
            } else if ("--port".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            }
        }

        banner(suiteArg, host, port);

        if ("CLASSICAL".equalsIgnoreCase(suiteArg)) {
            runClassicalClient(host, port);
        } else {
            runHybridClient(host, port, suiteArg);
        }
    }

    private static void runHybridClient(String host, int port, String suite) throws Exception {
        PublicKey pinnedKey = null;
        if (Files.exists(PINNED_KEY_PATH)) {
            pinnedKey = MlDsaSignatureScheme.loadPinnedPublicKey(PINNED_KEY_PATH);
            System.out.printf("[CLIENT] Loaded pinned ML-DSA-65 server key (%d bytes)%n", pinnedKey.getEncoded().length);
        } else {
            System.out.println("[CLIENT] [WARN] Pinned key file not found on disk; skipping auth validation.");
        }

        try (Socket socket = new Socket(host, port)) {
            System.out.printf("[CLIENT] Connected to %s:%d - initiating handshake%n", host, port);
            System.out.println("─".repeat(70));

            HybridHandshake.HandshakeOutcome outcome =
                    HybridHandshake.clientHandshake(socket, pinnedKey, List.of(suite));

            System.out.println("─".repeat(70));
            System.out.printf("[CLIENT] Handshake completed successfully with suite: %s%n", outcome.chosenSuite());

            try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                    socket, outcome.sessionKeys(), true, HandshakeConfig.safe())) {

                for (int i = 1; i <= 3; i++) {
                    String msg = "Secure message from client [" + i + "/3] via " + suite;
                    channel.send(msg.getBytes(StandardCharsets.UTF_8));
                    System.out.printf("[CLIENT] Sent     [%d/3]: \"%s\"%n", i, msg);

                    byte[] reply = channel.receive();
                    System.out.printf("[CLIENT] Received [%d/3]: \"%s\"%n", i,
                            new String(reply, StandardCharsets.UTF_8));
                }
            }
            System.out.println("[CLIENT] Session completed securely.");
        }
    }

    private static void runClassicalClient(String host, int port) throws Exception {
        System.out.println("[CLIENT] Running in legacy CLASSICAL mode...");
        try (Socket socket = new Socket(host, port)) {
            SessionKeys keys = ClassicalHandshake.clientHandshake(socket, HandshakeConfig.safe(), null);
            try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                    socket, keys, true, HandshakeConfig.safe())) {
                for (int i = 1; i <= 3; i++) {
                    String msg = "Classical message [" + i + "/3]";
                    channel.send(msg.getBytes(StandardCharsets.UTF_8));
                    byte[] reply = channel.receive();
                    System.out.printf("[CLIENT] Received [%d/3]: \"%s\"%n", i,
                            new String(reply, StandardCharsets.UTF_8));
                }
            }
        }
    }

    private static void banner(String suite, String host, int port) {
        System.out.println("═".repeat(70));
        System.out.printf("  PQC-APS :: SECURE CLIENT DEMO [Suite: %s, Host: %s, Port: %d]%n", suite, host, port);
        System.out.println("═".repeat(70));
    }
}
