package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.EncryptedRecord;
import com.pqcaps.common.HandshakeConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies that after a successful handshake in both HYBRID and PQ_ONLY modes:
 * 1. Multiple messages flow and decrypt correctly.
 * 2. Sequence numbers monotonically increase.
 * 3. Replayed records are detected and rejected.
 */
class DataFlowAndReplayTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    @DisplayName("HYBRID channel: multi-message data flow, sequence number increments, and replay rejection")
    void testHybridDataFlowAndReplayRejection() throws Exception {
        runDataFlowAndReplayTestForSuite("HYBRID");
    }

    @Test
    @DisplayName("PQ_ONLY channel: multi-message data flow, sequence number increments, and replay rejection")
    void testPqOnlyDataFlowAndReplayRejection() throws Exception {
        runDataFlowAndReplayTestForSuite("PQ_ONLY");
    }

    private void runDataFlowAndReplayTestForSuite(String suite) throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<Boolean> serverFuture = exec.submit(() -> {
            try (Socket s = serverSocket.accept()) {
                HybridHandshake.HandshakeOutcome ho = HybridHandshake.serverHandshake(s, serverSigningKp.getPrivate(), false);
                try (ClassicalSecureChannel ch = new ClassicalSecureChannel(s, ho.sessionKeys(), false, HandshakeConfig.hardened())) {

                    // 1. Receive 3 sequential messages
                    for (int i = 0; i < 3; i++) {
                        byte[] data = ch.receive();
                        String text = new String(data, StandardCharsets.UTF_8);
                        assertThat(text).isEqualTo("Payload #" + i);
                        assertThat(ch.getRecvSeq()).isEqualTo(i + 1);
                    }

                    // 2. Receive replayed record (seq=0) -> MUST throw SecurityException!
                    try {
                        ch.receive();
                        return false; // Failed: accepted replayed record
                    } catch (SecurityException se) {
                        assertThat(se.getMessage()).containsIgnoringCase("replay");
                        // Ensure recvSeq was not corrupted by the replayed record
                        assertThat(ch.getRecvSeq()).isEqualTo(3);
                        return true;
                    }
                }
            }
        });

        Future<Boolean> clientFuture = exec.submit(() -> {
            try (Socket s = new Socket("127.0.0.1", port)) {
                HybridHandshake.HandshakeOutcome ho =
                        HybridHandshake.clientHandshake(s, serverSigningKp.getPublic(), List.of(suite));

                ObjectOutputStream rawOut = new ObjectOutputStream(s.getOutputStream());
                rawOut.flush();

                // Send 3 messages using the secure channel
                ClassicalSecureChannel ch = new ClassicalSecureChannel(rawOut, null, ho.sessionKeys(), true, HandshakeConfig.hardened());

                // We capture the ciphertext of message 0 to replay later
                byte[] nonce0 = ClassicalSecureChannel.buildNonce(0);
                byte[] aad0 = ClassicalSecureChannel.buildAad(0);
                byte[] ct0 = new com.pqcaps.classical.AesGcmCipher().encrypt(
                        ho.sessionKeys().clientToServer(), nonce0, aad0, "Payload #0".getBytes(StandardCharsets.UTF_8));
                EncryptedRecord record0 = new EncryptedRecord(0, nonce0, ct0);

                // Send 3 normal messages (seq 0, 1, 2)
                ch.send("Payload #0".getBytes(StandardCharsets.UTF_8));
                ch.send("Payload #1".getBytes(StandardCharsets.UTF_8));
                ch.send("Payload #2".getBytes(StandardCharsets.UTF_8));
                assertThat(ch.getSendSeq()).isEqualTo(3);

                // Replay record 0 (sequence number 0 sent again after seq 2)
                rawOut.writeObject(record0);
                rawOut.flush();

                return true;
            }
        });

        assertThat(clientFuture.get(5, TimeUnit.SECONDS)).isTrue();
        assertThat(serverFuture.get(5, TimeUnit.SECONDS)).isTrue();

        serverSocket.close();
        exec.shutdown();
    }
}
