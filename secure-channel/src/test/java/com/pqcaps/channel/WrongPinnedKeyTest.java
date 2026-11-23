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
 * Validates that the client strictly enforces pinned ML-DSA-65 server identity:
 *
 * <p>If a Rogue / MITM server signs the transcript with its own ML-DSA-65 private key,
 * but the client has pinned the legitimate server's public key, the client aborts
 * immediately at Step 5 with {@link SecurityException}.
 */
class WrongPinnedKeyTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    void clientAbortsWhenServerSignatureUsesUnpinnedKey() throws Exception {
        KeyPair legitimateServerKp = dsa.generateKeyPair();
        KeyPair rogueServerKp = dsa.generateKeyPair(); // Rogue attacker's keypair

        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        // Rogue server signs with its own rogue key
        executor.submit(() -> {
            try (Socket socket = serverSocket.accept()) {
                HybridHandshake.serverHandshake(socket, rogueServerKp.getPrivate(), false);
            } catch (Exception ignored) {
            }
        });

        // Client connects with legitimate pinned public key
        Future<?> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                HybridHandshake.clientHandshake(
                        socket, legitimateServerKp.getPublic(), List.of("HYBRID"));
                return null;
            }
        });

        // Client MUST abort with SecurityException
        assertThatThrownBy(() -> clientFuture.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(SecurityException.class)
                .hasMessageContaining("Server identity signature verification failed");

        serverSocket.close();
        executor.shutdown();
    }
}
