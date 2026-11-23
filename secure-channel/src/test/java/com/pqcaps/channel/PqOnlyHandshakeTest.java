package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalSecureChannel;
import com.pqcaps.common.HandshakeConfig;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates the {@code PQ_ONLY} algorithm suite:
 *
 * <p>Flow:
 * <ul>
 *   <li>Relies solely on ML-KEM-768 for key encapsulation.</li>
 *   <li>Relies solely on ML-DSA-65 for transcript authentication.</li>
 *   <li>No classical X25519 component: {@code xpk_c}, {@code xpk_s}, and {@code ss1} are omitted.</li>
 *   <li>Complete post-quantum secure channel opens and cleanly encrypts/decrypts data.</li>
 * </ul>
 */
class PqOnlyHandshakeTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    void pqOnlyHandshakeWorksEndToEndWithoutClassicalKex() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        Future<HybridHandshake.HandshakeOutcome> serverFuture = executor.submit(() -> {
            try (Socket socket = serverSocket.accept()) {
                return HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);
            }
        });

        Future<HybridHandshake.HandshakeOutcome> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                return HybridHandshake.clientHandshake(socket, serverSigningKp.getPublic(), List.of("PQ_ONLY"));
            }
        });

        HybridHandshake.HandshakeOutcome serverOutcome = serverFuture.get(10, TimeUnit.SECONDS);
        HybridHandshake.HandshakeOutcome clientOutcome = clientFuture.get(10, TimeUnit.SECONDS);

        assertThat(serverOutcome.chosenSuite()).isEqualTo("PQ_ONLY");
        assertThat(clientOutcome.chosenSuite()).isEqualTo("PQ_ONLY");

        // Both sides derive matching session keys
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
    void pqOnlyDataExchangeOverChannel() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        Future<String> serverFuture = executor.submit(() -> {
            try (Socket socket = serverSocket.accept()) {
                HybridHandshake.HandshakeOutcome outcome =
                        HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);

                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        socket, outcome.sessionKeys(), false, HandshakeConfig.safe())) {
                    byte[] received = channel.receive();
                    channel.send("ACK from PQ_ONLY Server".getBytes(StandardCharsets.UTF_8));
                    return new String(received, StandardCharsets.UTF_8);
                }
            }
        });

        Future<String> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                HybridHandshake.HandshakeOutcome outcome =
                        HybridHandshake.clientHandshake(socket, serverSigningKp.getPublic(), List.of("PQ_ONLY"));

                try (ClassicalSecureChannel channel = new ClassicalSecureChannel(
                        socket, outcome.sessionKeys(), true, HandshakeConfig.safe())) {
                    channel.send("MSG from PQ_ONLY Client".getBytes(StandardCharsets.UTF_8));
                    byte[] reply = channel.receive();
                    return new String(reply, StandardCharsets.UTF_8);
                }
            }
        });

        String serverReceived = serverFuture.get(10, TimeUnit.SECONDS);
        String clientReceived = clientFuture.get(10, TimeUnit.SECONDS);

        assertThat(serverReceived).isEqualTo("MSG from PQ_ONLY Client");
        assertThat(clientReceived).isEqualTo("ACK from PQ_ONLY Server");

        serverSocket.close();
        executor.shutdown();
    }
}
