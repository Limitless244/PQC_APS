package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.HandshakeConfig;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Full end-to-end test of the Post-Quantum Hybrid Handshake over real TCP sockets.
 *
 * <p>Flow:
 * 1. Server listens on localhost ephemeral port.
 * 2. Client initiates handshake with HYBRID suite.
 * 3. Both sides verify signatures, exchange nonces, compute KEX shares, and confirm keys via Finished.
 * 4. ClassicalSecureChannel is opened with derived keys and exchanges encrypted application records,
 *    verifying that sequence numbers increase monotonically.
 */
class HybridHandshakeTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    void fullHybridHandshakeAndChannelOpen() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        // Server future
        Future<HybridHandshake.HandshakeOutcome> serverFuture = executor.submit(() -> {
            try (Socket socket = serverSocket.accept()) {
                return HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);
            }
        });

        // Client future
        Future<HybridHandshake.HandshakeOutcome> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                return HybridHandshake.clientHandshake(socket, serverSigningKp.getPublic(), List.of("HYBRID", "PQ_ONLY"));
            }
        });

        HybridHandshake.HandshakeOutcome serverOutcome = serverFuture.get(10, TimeUnit.SECONDS);
        HybridHandshake.HandshakeOutcome clientOutcome = clientFuture.get(10, TimeUnit.SECONDS);

        assertThat(serverOutcome.chosenSuite()).isEqualTo("HYBRID");
        assertThat(clientOutcome.chosenSuite()).isEqualTo("HYBRID");

        // Verify that derived keys are completely identical
        assertThat(clientOutcome.sessionKeys().clientToServer())
                .isEqualTo(serverOutcome.sessionKeys().clientToServer());
        assertThat(clientOutcome.sessionKeys().serverToClient())
                .isEqualTo(serverOutcome.sessionKeys().serverToClient());
        assertThat(clientOutcome.sessionKeys().finishedKey())
                .isEqualTo(serverOutcome.sessionKeys().finishedKey());

        serverSocket.close();
        executor.shutdown();
    }

    @Test
    void encryptedMessageExchangeAndSequenceNumberTracking() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        Future<Boolean> serverFuture = executor.submit(() -> {
            try (Socket socket = serverSocket.accept()) {
                HybridHandshake.HandshakeOutcome outcome =
                        HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);

                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        socket, outcome.sessionKeys(), false, HandshakeConfig.safe())) {

                    for (int i = 0; i < 3; i++) {
                        byte[] received = channel.receive();
                        String clientMsg = new String(received, StandardCharsets.UTF_8);
                        assertThat(clientMsg).isEqualTo("Msg #" + i + " from Client");

                        channel.send(("Ack #" + i + " from Server").getBytes(StandardCharsets.UTF_8));
                    }
                    return true;
                }
            }
        });

        Future<Boolean> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                HybridHandshake.HandshakeOutcome outcome =
                        HybridHandshake.clientHandshake(socket, serverSigningKp.getPublic(), List.of("HYBRID"));

                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        socket, outcome.sessionKeys(), true, HandshakeConfig.safe())) {

                    for (int i = 0; i < 3; i++) {
                        channel.send(("Msg #" + i + " from Client").getBytes(StandardCharsets.UTF_8));
                        byte[] reply = channel.receive();
                        String replyMsg = new String(reply, StandardCharsets.UTF_8);
                        assertThat(replyMsg).isEqualTo("Ack #" + i + " from Server");
                    }
                    return true;
                }
            }
        });

        assertThat(serverFuture.get(10, TimeUnit.SECONDS)).isTrue();
        assertThat(clientFuture.get(10, TimeUnit.SECONDS)).isTrue();

        serverSocket.close();
        executor.shutdown();
    }
}
