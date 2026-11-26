package com.pqcaps.channel.demo;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.channel.HybridHandshake;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;

/**
 * Post-Quantum & Hybrid secure channel TCP Server demo.
 *
 * <p>Supports {@code --suite HYBRID|PQ_ONLY|CLASSICAL} (default: HYBRID).
 */
public final class HybridServer {

    private static final int DEFAULT_PORT = 9000;
    private static final Path PINNED_KEY_PATH = Path.of("server_identity_mldsa65.key");

    public static void main(String[] args) throws Exception {
        String suiteArg = "HYBRID";
        int port = DEFAULT_PORT;

        for (int i = 0; i < args.length; i++) {
            if ("--suite".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                suiteArg = args[++i].toUpperCase();
            } else if ("--port".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            }
        }

        banner(suiteArg, port);

        if ("CLASSICAL".equalsIgnoreCase(suiteArg)) {
            runClassicalServer(port);
        } else {
            runHybridServer(port, suiteArg);
        }
    }

    private static void runHybridServer(int port, String suite) throws Exception {
        MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();
        KeyPair identityKp = dsa.generateKeyPair();
        MlDsaSignatureScheme.savePinnedPublicKey(identityKp.getPublic(), PINNED_KEY_PATH);

        System.out.println("[SERVER] Generated ML-DSA-65 identity keypair (FIPS 204)");
        System.out.printf("[SERVER] Public key size: %d bytes (raw: 1952 B)%n", identityKp.getPublic().getEncoded().length);
        System.out.printf("[SERVER] Saved pinned key to: %s%n%n", PINNED_KEY_PATH.toAbsolutePath());

        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.printf("[SERVER] Listening on port %d...%n", port);
            try (Socket socket = ss.accept()) {
                System.out.println("[SERVER] Client connected - starting 8-step Hybrid handshake");
                System.out.println("─".repeat(70));

                HybridHandshake.HandshakeOutcome outcome =
                        HybridHandshake.serverHandshake(socket, identityKp.getPrivate(), false);

                System.out.println("─".repeat(70));
                System.out.printf("[SERVER] Handshake completed successfully with suite: %s%n", outcome.chosenSuite());

                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        socket, outcome.sessionKeys(), false, HandshakeConfig.safe())) {

                    for (int i = 1; i <= 3; i++) {
                        byte[] msg = channel.receive();
                        String text = new String(msg, StandardCharsets.UTF_8);
                        System.out.printf("[SERVER] Received [%d/3]: \"%s\"%n", i, text);

                        String reply = "PQC-ACK: received '" + text + "' (protected by AES-256-GCM)";
                        channel.send(reply.getBytes(StandardCharsets.UTF_8));
                        System.out.printf("[SERVER] Sent     [%d/3]: \"%s\"%n", i, reply);
                    }
                }
            }
        }
    }

    private static void runClassicalServer(int port) throws Exception {
        System.out.println("[SERVER] Running in legacy CLASSICAL mode (vulnerable baseline)...");
        KeyPair serverIdentity = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();

        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.printf("[SERVER] Listening on port %d...%n", port);
            try (Socket socket = ss.accept()) {
                SessionKeys keys = ClassicalHandshake.serverHandshake(socket, HandshakeConfig.safe(), serverIdentity);
                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        socket, keys, false, HandshakeConfig.safe())) {
                    for (int i = 1; i <= 3; i++) {
                        channel.receive();
                        String reply = "Classical ACK [" + i + "/3]";
                        channel.send(reply.getBytes(StandardCharsets.UTF_8));
                    }
                }
            }
        }
    }

    private static void banner(String suite, int port) {
        System.out.println("═".repeat(70));
        System.out.printf("  PQC-APS :: SECURE SERVER DEMO [Suite: %s, Port: %d]%n", suite, port);
        System.out.println("═".repeat(70));
    }
}
