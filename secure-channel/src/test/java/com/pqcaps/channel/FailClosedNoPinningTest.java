package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Validates FAIL-CLOSED behavior:
 *
 * <p>By default, HYBRID and PQ_ONLY client handshakes MUST abort immediately with
 * a {@link SecurityException} if no pinned server public key is provided, unless
 * {@code allowInsecureNoPinning=true} is explicitly supplied.
 */
class FailClosedNoPinningTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    void hybridClientAbortsWhenNoPinnedKeyProvidedByDefault() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        executor.submit(() -> {
            try (Socket socket = serverSocket.accept()) {
                HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);
            } catch (Exception ignored) {
            }
        });

        // Client attempts handshake with pinnedServerKey = null and default allowInsecureNoPinning = false
        Future<?> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                // Default 3-arg clientHandshake has allowInsecureNoPinning = false
                HybridHandshake.clientHandshake(socket, null, List.of("HYBRID"));
                return null;
            }
        });

        assertThatThrownBy(() -> clientFuture.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(SecurityException.class)
                .hasMessageContaining("FAIL-CLOSED: Pinned server public key is required");

        serverSocket.close();
        executor.shutdown();
    }

    @Test
    void pqOnlyClientAbortsWhenNoPinnedKeyProvidedByDefault() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        executor.submit(() -> {
            try (Socket socket = serverSocket.accept()) {
                HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);
            } catch (Exception ignored) {
            }
        });

        Future<?> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                HybridHandshake.clientHandshake(socket, null, List.of("PQ_ONLY"));
                return null;
            }
        });

        assertThatThrownBy(() -> clientFuture.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(SecurityException.class)
                .hasMessageContaining("FAIL-CLOSED: Pinned server public key is required");

        serverSocket.close();
        executor.shutdown();
    }
}
