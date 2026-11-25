package com.pqcaps.classical;

import com.pqcaps.common.HandshakeConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
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

class HardenedClassicalSessionTest {

    @Test
    @DisplayName("Hardened classical session executes handshake and bidirectional data transfer with ZERO [VULN-n] warnings")
    void hardenedClassicalSessionEmitsZeroVulnWarnings() throws Exception {
        // Intercept System.out
        PrintStream originalOut = System.out;
        ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(capturedOut, true, StandardCharsets.UTF_8));

        try {
            HandshakeConfig hardenedConfig = HandshakeConfig.hardened();
            assertThat(hardenedConfig.isHardened()).isTrue();
            assertThat(hardenedConfig.isSkipSuiteSignature()).isFalse();
            assertThat(hardenedConfig.isSkipSequenceCheck()).isFalse();
            assertThat(hardenedConfig.isUnsafeNonceMode()).isFalse();
            assertThat(hardenedConfig.isSkipKeyPinning()).isFalse();

            KeyPair serverIdentity = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();
            ServerSocket serverSocket = new ServerSocket(0);
            int port = serverSocket.getLocalPort();
            ExecutorService exec = Executors.newFixedThreadPool(2);

            Future<Boolean> serverFuture = exec.submit(() -> {
                try (Socket s = serverSocket.accept()) {
                    ClassicalHandshake.HandshakeOutcome ho =
                            ClassicalHandshake.serverHandshakeFull(s, hardenedConfig, serverIdentity);
                    try (ClassicalSecureChannel ch = new ClassicalSecureChannel(s, ho.sessionKeys(), false, hardenedConfig)) {
                        byte[] clientMsg = ch.receive();
                        assertThat(new String(clientMsg, StandardCharsets.UTF_8)).isEqualTo("Client Ping");
                        ch.send("Server Pong".getBytes(StandardCharsets.UTF_8));
                        return true;
                    }
                }
            });

            Future<Boolean> clientFuture = exec.submit(() -> {
                try (Socket s = new Socket("127.0.0.1", port)) {
                    ClassicalHandshake.HandshakeOutcome ho =
                            ClassicalHandshake.clientHandshakeFull(s, hardenedConfig, serverIdentity.getPublic(), List.of("CLASSICAL"));
                    try (ClassicalSecureChannel ch = new ClassicalSecureChannel(s, ho.sessionKeys(), true, hardenedConfig)) {
                        ch.send("Client Ping".getBytes(StandardCharsets.UTF_8));
                        byte[] reply = ch.receive();
                        assertThat(new String(reply, StandardCharsets.UTF_8)).isEqualTo("Server Pong");
                        return true;
                    }
                }
            });

            assertThat(serverFuture.get(5, TimeUnit.SECONDS)).isTrue();
            assertThat(clientFuture.get(5, TimeUnit.SECONDS)).isTrue();

            serverSocket.close();
            exec.shutdown();

            String output = capturedOut.toString(StandardCharsets.UTF_8);
            System.err.println("Captured output length: " + output.length());

            // Assert ZERO occurrences of [VULN-n] warnings in hardened session output
            assertThat(output).doesNotContain("[VULN-");
            assertThat(output).doesNotContain("[VULN-1]");
            assertThat(output).doesNotContain("[VULN-2]");
            assertThat(output).doesNotContain("[VULN-3]");
            assertThat(output).doesNotContain("[VULN-4]");
        } finally {
            System.setOut(originalOut);
        }
    }
}
