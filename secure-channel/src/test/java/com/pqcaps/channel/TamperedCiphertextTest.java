package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.common.ClientHello;
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
 * Proves that tampering with the ML-KEM encapsulation ciphertext during transit
 * causes the server's Finished message verification to FAIL due to ML-KEM implicit rejection,
 * and mutual key confirmation ensures client also aborts without reporting success.
 */
class TamperedCiphertextTest {

    private final MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();

    @Test
    @DisplayName("Tampered ML-KEM ciphertext causes Finished verification failure and abort on both ends")
    void tamperedCiphertextCausesFinishedVerificationFailure() throws Exception {
        KeyPair serverSigningKp = dsa.generateKeyPair();

        ServerSocket realServer = new ServerSocket(0);
        int realPort = realServer.getLocalPort();

        ServerSocket proxyServer = new ServerSocket(0);
        int proxyPort = proxyServer.getLocalPort();

        ExecutorService executor = Executors.newFixedThreadPool(3);

        // Server task
        Future<Exception> serverErrorFuture = executor.submit(() -> {
            try (Socket socket = realServer.accept()) {
                HybridHandshake.serverHandshake(socket, serverSigningKp.getPrivate(), false);
                return null; // Should not reach here
            } catch (Exception e) {
                return e;
            }
        });

        // Proxy task: forwards ClientHello, tampers ServerHello ct, forwards Finished
        executor.submit(() -> {
            try (Socket clientSock = proxyServer.accept();
                 Socket serverSock = new Socket("127.0.0.1", realPort)) {

                ObjectOutputStream outToServer = new ObjectOutputStream(serverSock.getOutputStream());
                outToServer.flush();
                ObjectInputStream inFromServer = new ObjectInputStream(serverSock.getInputStream());

                ObjectOutputStream outToClient = new ObjectOutputStream(clientSock.getOutputStream());
                outToClient.flush();
                ObjectInputStream inFromClient = new ObjectInputStream(clientSock.getInputStream());

                // Forward ClientHello unmodified
                ClientHello ch = (ClientHello) inFromClient.readObject();
                outToServer.writeObject(ch);
                outToServer.flush();

                // Intercept ServerHello and TAMPER with ct (flip 1 byte)
                ServerHello sh = (ServerHello) inFromServer.readObject();
                byte[] tamperedCt = sh.ct().clone();
                tamperedCt[10] ^= 0x01; // Attacker bit flip!

                ServerHello tamperedSh = new ServerHello(
                        sh.xpk_s(), tamperedCt, sh.chosenSuite(), sh.nonce_s(), sh.signature());
                outToClient.writeObject(tamperedSh);
                outToClient.flush();

                // Forward client's Finished message to server
                FinishedMessage fin = (FinishedMessage) inFromClient.readObject();
                outToServer.writeObject(fin);
                outToServer.flush();

                // Forward server Finished if any
                try {
                    FinishedMessage serverFin = (FinishedMessage) inFromServer.readObject();
                    outToClient.writeObject(serverFin);
                    outToClient.flush();
                } catch (Exception ignored) {}

            } catch (Exception ignored) {
            }
        });

        // Client task: connects through the proxy (with explicit allowInsecureNoPinning=true to isolate KEM Finished rejection)
        Future<HybridHandshake.HandshakeOutcome> clientFuture = executor.submit(() -> {
            try (Socket socket = new Socket("127.0.0.1", proxyPort)) {
                return HybridHandshake.clientHandshake(socket, null, List.of("HYBRID"), true);
            }
        });

        // Server MUST throw SecurityException at step 6 when verifying Finished tag!
        Exception serverError = serverErrorFuture.get(10, TimeUnit.SECONDS);
        assertThat(serverError)
                .isNotNull()
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("handshake failed");

        // Mutual key confirmation: Client MUST NOT report success because server aborted before Finished confirmation!
        assertThatThrownBy(() -> clientFuture.get(10, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(SecurityException.class);

        realServer.close();
        proxyServer.close();
        executor.shutdown();
    }
}
