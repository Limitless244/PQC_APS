package com.pqcaps.classical.demo;

import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;

import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Classical secure-channel demo — TCP Client.
 *
 * <p>Connects to {@link ClassicalServer} on localhost:9000, performs the classical
 * handshake with key-pinning <em>disabled</em> (VULN-4), then sends 3 encrypted
 * messages and prints the server's replies.
 *
 * <p>Run after starting {@link ClassicalServer}:
 * {@code java -cp ... com.pqcaps.classical.demo.ClassicalClient}
 */
public final class ClassicalClient {

    private static final String HOST = "localhost";
    private static final int    PORT = 9000;

    public static void main(String[] args) throws Exception {
        banner();

        // VULN-4: skipKeyPinning=true — client accepts ANY server key.
        // Phase 4 will pin the server's RSA public key so MITM is detected.
        HandshakeConfig config = HandshakeConfig.vulnerable();

        System.out.println("[CLIENT] Connecting to " + HOST + ":" + PORT);
        try (Socket socket = new Socket(HOST, PORT)) {
            System.out.println("[CLIENT] Connected — starting handshake");
            System.out.println("─".repeat(60));

            // pinnedServerKey = null because VULN-4 (skipKeyPinning) is true
            SessionKeys keys = ClassicalHandshake.clientHandshake(socket, config, null);
            System.out.println("─".repeat(60));

            try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                    socket, keys, true /* isClient */, config)) {

                for (int i = 1; i <= 3; i++) {
                    String msg = "Hello from client [" + i + "/3]";
                    channel.send(msg.getBytes(StandardCharsets.UTF_8));
                    System.out.printf("[CLIENT] Sent    [%d/3]: \"%s\"%n", i, msg);

                    byte[] reply = channel.receive();
                    System.out.printf("[CLIENT] Received[%d/3]: \"%s\"%n", i,
                            new String(reply, StandardCharsets.UTF_8));
                }
            }
            System.out.println("[CLIENT] Session complete.");
        }
    }

    private static void banner() {
        System.out.println("═".repeat(60));
        System.out.println("  PQC-APS :: Classical Baseline Demo — CLIENT");
        System.out.println("  ⚠  INTENTIONALLY VULNERABLE — Phase 1 Baseline ⚠");
        System.out.println("═".repeat(60));
        System.out.println();
    }
}
