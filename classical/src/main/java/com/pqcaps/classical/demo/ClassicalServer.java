package com.pqcaps.classical.demo;

import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

/**
 * Classical secure-channel demo — TCP Server.
 *
 * <p>Generates a long-lived RSA-2048 identity keypair, listens on port 9000,
 * performs the classical handshake with the first connecting client, then
 * exchanges 3 encrypted messages.
 *
 * <p>All four vulnerabilities are ACTIVE (Phase 1 defaults):
 * <ul>
 *   <li>VULN-1: suite list not covered by signature.</li>
 *   <li>VULN-2: sequence numbers not enforced.</li>
 *   <li>VULN-3: nonce counter resets on each new channel.</li>
 *   <li>VULN-4: (client decides whether to pin the key; server always signs).</li>
 * </ul>
 *
 * <p>Run: {@code java -cp ... com.pqcaps.classical.demo.ClassicalServer}
 * Then in another terminal: {@code java -cp ... com.pqcaps.classical.demo.ClassicalClient}
 */
public final class ClassicalServer {

    private static final int PORT = 9000;

    public static void main(String[] args) throws Exception {
        banner();
        HandshakeConfig config = HandshakeConfig.vulnerable(); // VULN-1,2,3,4 all on

        // ── Generate long-lived server identity (RSA-2048) ────────────────────
        System.out.println("[SERVER] Generating RSA-2048 identity keypair…");
        KeyPair serverIdentity = ClassicalCryptoSuite.getInstance()
                .signatureScheme().generateKeyPair();
        byte[] encodedPubKey = serverIdentity.getPublic().getEncoded();
        System.out.printf("[SERVER] Server public key (DER): %s…  (%d bytes total)%n",
                ClassicalHandshake.hex4(encodedPubKey), encodedPubKey.length);
        System.out.println("[SERVER] In a real system, distribute this key to clients out-of-band.");
        System.out.println();

        try (ServerSocket ss = new ServerSocket(PORT)) {
            System.out.printf("[SERVER] Listening on port %d…%n%n", PORT);
            try (Socket client = ss.accept()) {
                System.out.println("[SERVER] Client connected — starting handshake");
                System.out.println("─".repeat(60));

                // ── Handshake ─────────────────────────────────────────────────
                SessionKeys keys = ClassicalHandshake.serverHandshake(client, config, serverIdentity);
                System.out.println("─".repeat(60));

                // ── Secure messaging via AES-GCM record layer ─────────────────
                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        client, keys, false /* isServer */, config)) {

                    // Receive 3 messages from client, echo each back uppercased
                    for (int i = 1; i <= 3; i++) {
                        byte[] msg = channel.receive();
                        String text = new String(msg, StandardCharsets.UTF_8);
                        System.out.printf("[SERVER] Received [%d/3]: \"%s\"%n", i, text);

                        String reply = "Echo: " + text.toUpperCase();
                        channel.send(reply.getBytes(StandardCharsets.UTF_8));
                        System.out.printf("[SERVER] Sent    [%d/3]: \"%s\"%n", i, reply);
                    }
                }
                System.out.println("[SERVER] Session complete.");
            }
        }
    }

    private static void banner() {
        System.out.println("═".repeat(60));
        System.out.println("  PQC-APS :: Classical Baseline Demo — SERVER");
        System.out.println("  ⚠  INTENTIONALLY VULNERABLE — Phase 1 Baseline ⚠");
        System.out.println("═".repeat(60));
        System.out.println();
    }
}
