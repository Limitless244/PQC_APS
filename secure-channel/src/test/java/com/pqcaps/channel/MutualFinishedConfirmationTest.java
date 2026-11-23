package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.common.FinishedMessage;
import com.pqcaps.common.ServerHello;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for Mutual Key Confirmation in HybridHandshake.
 * Both client and server must exchange and verify Finished messages.
 * If either party aborts or tampers with Finished verifyData, the handshake MUST fail.
 */
class MutualFinishedConfirmationTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    @DisplayName("Mutual Finished key confirmation succeeds for HYBRID suite")
    void normalHandshakeSucceedsWithMutualFinished() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<HybridHandshake.HandshakeOutcome> sFuture = exec.submit(() -> {
            try (Socket s = serverSocket.accept()) {
                return HybridHandshake.serverHandshake(s, serverSigningKp.getPrivate(), false);
            }
        });

        Future<HybridHandshake.HandshakeOutcome> cFuture = exec.submit(() -> {
            try (Socket s = new Socket("127.0.0.1", port)) {
                return HybridHandshake.clientHandshake(s, serverSigningKp.getPublic(), List.of("HYBRID"));
            }
        });

        HybridHandshake.HandshakeOutcome sOut = sFuture.get(5, TimeUnit.SECONDS);
        HybridHandshake.HandshakeOutcome cOut = cFuture.get(5, TimeUnit.SECONDS);

        assertThat(sOut).isNotNull();
        assertThat(cOut).isNotNull();
        assertThat(sOut.chosenSuite()).isEqualTo("HYBRID");
        assertThat(cOut.chosenSuite()).isEqualTo("HYBRID");

        serverSocket.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("Client aborts when server sends invalid Finished verifyData")
    void clientAbortsWhenServerFinishedCorrupted() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();
        ExecutorService exec = Executors.newFixedThreadPool(2);

        // Server sends bad Finished verifyData instead of valid HMAC tag
        exec.submit(() -> {
            try (Socket s = serverSocket.accept()) {
                ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
                out.flush();
                ObjectInputStream in = new ObjectInputStream(s.getInputStream());

                // Read ClientHello
                in.readObject();

                // Build & send regular ServerHello
                var kem = new com.pqcaps.kex.MlKemKeyExchange();
                var kemKp = kem.generateKeyPair();
                var encRes = kem.encapsulate(kemKp.getPublic());
                var xkex = new com.pqcaps.classical.X25519KeyExchange();
                var xKp = xkex.generateKeyPair();

                byte[] dummySig = dsa.sign(serverSigningKp.getPrivate(), new byte[32]);
                ServerHello sh = new ServerHello(xKp.getPublic().getEncoded(), encRes.ciphertext(), "HYBRID", new byte[32], dummySig);
                out.writeObject(sh);
                out.flush();

                // Read Client Finished
                in.readObject();

                // Send BAD Server Finished
                FinishedMessage badServerFin = new FinishedMessage(new byte[32]); // Corrupt zero bytes
                out.writeObject(badServerFin);
                out.flush();
            } catch (Exception ignored) {}
        });

        Future<?> cFuture = exec.submit(() -> {
            try (Socket s = new Socket("127.0.0.1", port)) {
                HybridHandshake.clientHandshake(s, null, List.of("HYBRID"), true);
                return null;
            }
        });

        assertThatThrownBy(() -> cFuture.get(5, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(SecurityException.class);

        serverSocket.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("Client aborts and does not report success when server aborts before Finished")
    void clientAbortsWhenServerDisconnectsBeforeFinished() throws Exception {
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();
        ExecutorService exec = Executors.newFixedThreadPool(2);

        // Server drops connection after receiving client Finished
        exec.submit(() -> {
            try (Socket s = serverSocket.accept()) {
                ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
                out.flush();
                ObjectInputStream in = new ObjectInputStream(s.getInputStream());

                in.readObject(); // ClientHello

                var kem = new com.pqcaps.kex.MlKemKeyExchange();
                var kemKp = kem.generateKeyPair();
                var encRes = kem.encapsulate(kemKp.getPublic());
                var xkex = new com.pqcaps.classical.X25519KeyExchange();
                var xKp = xkex.generateKeyPair();

                byte[] dummySig = new byte[3309];
                ServerHello sh = new ServerHello(xKp.getPublic().getEncoded(), encRes.ciphertext(), "HYBRID", new byte[32], dummySig);
                out.writeObject(sh);
                out.flush();

                in.readObject(); // Client Finished
                // Server intentionally aborts without sending server Finished
                s.close();
            } catch (Exception ignored) {}
        });

        Future<?> cFuture = exec.submit(() -> {
            try (Socket s = new Socket("127.0.0.1", port)) {
                HybridHandshake.clientHandshake(s, null, List.of("HYBRID"), true);
                return null;
            }
        });

        assertThatThrownBy(() -> cFuture.get(5, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(SecurityException.class);

        serverSocket.close();
        exec.shutdown();
    }
}
