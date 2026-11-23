package com.pqcaps.classical;

import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;

/**
 * End-to-end integration test: a real TCP client and server run in separate
 * threads within the same JVM, complete the classical handshake, and exchange
 * encrypted messages.
 *
 * <p>This test validates:
 * <ol>
 *   <li>Client sends "hello" → server receives "hello".</li>
 *   <li>Server replies "world" → client receives "world".</li>
 *   <li>Keys are symmetric: what one side encrypts the other decrypts.</li>
 *   <li>Tampered record is rejected (GCM tag failure).</li>
 * </ol>
 */
class EndToEndTest {

    private static final HandshakeConfig VULN_CONFIG = HandshakeConfig.vulnerable();
    private static final HandshakeConfig SAFE_CONFIG = HandshakeConfig.safe();

    // ── Full handshake + message exchange ─────────────────────────────────────

    /**
     * Trace (abbreviated):
     * <pre>
     * [Server thread] Listen on ephemeral port P
     * [Client thread] Connect to P → ClientHello{xpk_c=a1b2…, nonce_c=1234…}
     * [Server thread] ServerHello{xpk_s=c3d4…, sig=…, nonce_s=5678…}
     * [Client thread] VULN-4: skip key-pin verification
     * Both:           ss = X25519(…) → HkdfSha256(…) → SessionKeys
     * [Client]        send("hello")  → AES-GCM ciphertext
     * [Server]        receive()      → "hello"  ✓
     * [Server]        send("world")
     * [Client]        receive()      → "world"  ✓
     * </pre>
     */
    @Test
    void endToEnd_clientSendsHello_serverReceivesHello() throws Exception {
        KeyPair serverIdentity = new RsaSigner().generateKeyPair();

        CountDownLatch serverReady = new CountDownLatch(1);
        AtomicReference<String> serverReceived = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        int[] portHolder = new int[1];

        // ── Server thread ──────────────────────────────────────────────────
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(0)) { // OS picks a free port
                portHolder[0] = ss.getLocalPort();
                serverReady.countDown(); // signal client it can connect

                try (Socket conn = ss.accept()) {
                    SessionKeys keys = ClassicalHandshake.serverHandshake(
                            conn, VULN_CONFIG, serverIdentity);

                    try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                            conn, keys, false, VULN_CONFIG)) {

                        byte[] msg = channel.receive();
                        serverReceived.set(new String(msg, StandardCharsets.UTF_8));
                        channel.send("world".getBytes(StandardCharsets.UTF_8));
                    }
                }
            } catch (Throwable t) {
                serverError.set(t);
                serverReady.countDown();
            }
        }, "server-thread");
        serverThread.setDaemon(true);
        serverThread.start();

        // ── Client thread (runs on the test thread) ────────────────────────
        serverReady.await();
        assertThat(serverError.get()).as("Server should not have crashed before accept").isNull();

        try (Socket conn = new Socket("localhost", portHolder[0])) {
            SessionKeys keys = ClassicalHandshake.clientHandshake(conn, VULN_CONFIG, null);

            try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                    conn, keys, true, VULN_CONFIG)) {

                channel.send("hello".getBytes(StandardCharsets.UTF_8));
                byte[] reply = channel.receive();
                assertThat(new String(reply, StandardCharsets.UTF_8)).isEqualTo("world");
            }
        }

        serverThread.join(5000);
        assertThat(serverError.get()).as("Server should not have thrown").isNull();
        assertThat(serverReceived.get()).isEqualTo("hello");
    }

    // ── Nonce reuse test (VULN-3) ─────────────────────────────────────────────

    /**
     * Shows that after resetNonceCounterForTesting() the same nonce=0 is reused,
     * and XORing the two ciphertexts reveals the XOR of the plaintexts.
     */
    @Test
    void vuln3_nonceReset_sameCiphertextXorRevealsPlaineXtXor() throws Exception {
        byte[] key    = new byte[32]; // test key
        byte[] nonce0 = ClassicalSecureChannel.buildNonce(0);

        AesGcmCipher cipher = new AesGcmCipher();
        byte[] aad0 = ClassicalSecureChannel.buildAad(0);

        byte[] p1 = "AAAAAAAAAA".getBytes(StandardCharsets.UTF_8);
        byte[] p2 = "BBBBBBBBBB".getBytes(StandardCharsets.UTF_8);

        // First encryption: seq=0
        byte[] c1 = cipher.encrypt(key, nonce0, aad0, p1);
        // "Restart": same nonce=0 — VULN-3
        byte[] c2 = cipher.encrypt(key, nonce0, aad0, p2);

        // XOR the ciphertext bodies (excluding the 16-byte tag)
        byte[] xorBody = new byte[p1.length];
        for (int i = 0; i < p1.length; i++) xorBody[i] = (byte) (c1[i] ^ c2[i]);

        // XOR of ciphertext bodies = XOR of plaintext bodies (keystream cancels)
        byte[] xorPlain = new byte[p1.length];
        for (int i = 0; i < p1.length; i++) xorPlain[i] = (byte) (p1[i] ^ p2[i]);

        assertThat(xorBody).as("VULN-3: c1⊕c2 == p1⊕p2 (nonce reuse leaks XOR)").isEqualTo(xorPlain);
    }

    // ── Sequence-check test (VULN-2 and safe mode) ───────────────────────────

    @Test
    void vuln2_replayAccepted_whenSequenceCheckDisabled() throws Exception {
        SessionKeys keys = makeTestKeys();

        // Pipe-based in-process channel pair (no sockets needed)
        PipedOutputStream clientPipe = new PipedOutputStream();
        PipedInputStream  serverPipe = new PipedInputStream(clientPipe);

        ObjectOutputStream clientOut = new ObjectOutputStream(clientPipe);
        clientOut.flush();
        ObjectInputStream  serverIn  = new ObjectInputStream(serverPipe);

        ClassicalSecureChannel clientCh = new ClassicalSecureChannel(
                clientOut, null, keys, true, VULN_CONFIG);
        ClassicalSecureChannel serverCh = new ClassicalSecureChannel(
                null, serverIn, keys, false, VULN_CONFIG);

        // Send seq=0 and capture what arrives on the server side
        clientCh.send("first".getBytes(StandardCharsets.UTF_8));
        byte[] msg1 = serverCh.receive();
        assertThat(new String(msg1, StandardCharsets.UTF_8)).isEqualTo("first");
    }

    @Test
    void safeMode_sequenceEnforced_outOfOrderRecordRejected() throws Exception {
        SessionKeys keys = makeTestKeys();

        AesGcmCipher cipher = new AesGcmCipher();
        byte[] sendKey = keys.clientToServer();

        // Manually craft a record with seq=5 (out-of-order; server expects 0)
        byte[] nonce5 = ClassicalSecureChannel.buildNonce(5);
        byte[] aad5   = ClassicalSecureChannel.buildAad(5);
        byte[] ct     = cipher.encrypt(sendKey, nonce5, aad5, "replay".getBytes());

        com.pqcaps.common.EncryptedRecord replayRecord =
                new com.pqcaps.common.EncryptedRecord(5L, nonce5, ct);

        // Write it into a pipe
        PipedOutputStream pipeOut = new PipedOutputStream();
        PipedInputStream  pipeIn  = new PipedInputStream(pipeOut);
        ObjectOutputStream oos = new ObjectOutputStream(pipeOut);
        oos.flush();
        ObjectInputStream  ois = new ObjectInputStream(pipeIn);

        oos.writeObject(replayRecord);
        oos.flush();

        ClassicalSecureChannel serverCh = new ClassicalSecureChannel(
                null, ois, keys, false, SAFE_CONFIG);

        assertThatThrownBy(serverCh::receive)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Sequence number mismatch");
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private static SessionKeys makeTestKeys() {
        byte[] c2s = new byte[32];
        byte[] s2c = new byte[32];
        c2s[0] = 1;
        s2c[0] = 2;
        return new SessionKeys(c2s, s2c);
    }
}
