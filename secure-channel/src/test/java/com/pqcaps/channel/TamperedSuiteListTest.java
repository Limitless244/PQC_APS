package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.common.ClientHello;
import com.pqcaps.common.ServerHello;
import org.junit.jupiter.api.Test;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves that the Phase 2 Downgrade Attack (VULN-1) is COMPLETELY PREVENTED
 * in the Phase 3 Hybrid Handshake.
 *
 * <p>Why it succeeds in Phase 2:
 * In Phase 1, the server's signature did NOT cover {@code clientHello.suites()}.
 * An active MITM proxy was able to remove "HYBRID" and replace it with "CLASSICAL".
 *
 * <p>Why it FAILS in Phase 3:
 * The ML-DSA-65 signature covers the full transcript, including {@code clientHello.suites()}.
 * When the proxy tampers with the suite list, the client's locally computed transcript
 * (which retains {@code [HYBRID, PQ_ONLY]}) does not match the server's signed transcript
 * (which saw {@code [PQ_ONLY]}). Signature verification fails immediately on the client!
 */
class TamperedSuiteListTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    void downgradeAttackFailsDueToTranscriptSignatureBinding() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();

        ServerSocket realServer = new ServerSocket(0);
        int serverPort = realServer.getLocalPort();

        ServerSocket proxyServer = new ServerSocket(0);
        int proxyPort = proxyServer.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(3);

        // Real server accepts connection
        executor.submit(() -> {
            try (Socket socket = realServer.accept()) {
                HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);
            } catch (Exception ignored) {
            }
        });

        // Downgrade proxy: strips "HYBRID" and leaves only "PQ_ONLY" (or "CLASSICAL")
        executor.submit(() -> {
            try (Socket clientSock = proxyServer.accept();
                 Socket serverSock = new Socket("127.0.0.1", serverPort)) {

                ObjectOutputStream outToServer = new ObjectOutputStream(serverSock.getOutputStream());
                outToServer.flush();
                ObjectInputStream inFromServer = new ObjectInputStream(serverSock.getInputStream());

                ObjectOutputStream outToClient = new ObjectOutputStream(clientSock.getOutputStream());
                outToClient.flush();
                ObjectInputStream inFromClient = new ObjectInputStream(clientSock.getInputStream());

                // Read client hello: client offered [HYBRID, PQ_ONLY]
                ClientHello originalCh = (ClientHello) inFromClient.readObject();

                // Attacker modifies suite list: strips HYBRID
                ClientHello downgradedCh = new ClientHello(
                        originalCh.xpk_c(), originalCh.kpk_c(),
                        List.of("PQ_ONLY"), originalCh.nonce_c());
                outToServer.writeObject(downgradedCh);
                outToServer.flush();

                // Forward ServerHello back to client
                ServerHello sh = (ServerHello) inFromServer.readObject();
                outToClient.writeObject(sh);
                outToClient.flush();

            } catch (Exception ignored) {
            }
        });

        // Client initiates handshake offering [HYBRID, PQ_ONLY] with server key pinned
        Future<?> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", proxyPort)) {
                HybridHandshake.clientHandshake(
                        socket, serverSigningKp.getPublic(), List.of("HYBRID", "PQ_ONLY"));
                return null;
            }
        });

        // Handshake MUST fail on client because the server's signature does not match
        // the client's transcript containing original suites [HYBRID, PQ_ONLY]
        assertThatThrownBy(() -> clientFuture.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(SecurityException.class)
                .hasMessageContaining("Server identity signature verification failed");

        realServer.close();
        proxyServer.close();
        executor.shutdown();
    }
}
