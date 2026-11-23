package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.HandshakeObserver;
import com.pqcaps.common.HandshakeObserverContext;
import com.pqcaps.common.HandshakeStepEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Handshake Observer Verification")
class HandshakeObserverTest {

    @AfterEach
    void tearDown() {
        HandshakeObserverContext.setGlobalObserver(HandshakeObserver.NOOP);
    }

    @Test
    @DisplayName("HYBRID handshake emits expected ordered steps with non-zero sizes and valid hex4")
    void hybridHandshakeEmitsOrderedSteps() throws Exception {
        List<HandshakeStepEvent> captured = Collections.synchronizedList(new ArrayList<>());
        HandshakeObserverContext.setGlobalObserver((step, dir, bytes, hex4, outcome, ts) -> {
            captured.add(new HandshakeStepEvent(step, dir, bytes, hex4, outcome, ts));
        });

        MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();
        KeyPair sKp = dsa.generateKeyPair();

        try (ServerSocket server = new ServerSocket(0)) {
            int port = server.getLocalPort();
            ExecutorService exec = Executors.newFixedThreadPool(2);

            Future<?> serverFuture = exec.submit(() -> {
                try (Socket s = server.accept()) {
                    HybridHandshake.serverHandshake(s, sKp.getPrivate(), false);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            Future<?> clientFuture = exec.submit(() -> {
                try (Socket s = new Socket("127.0.0.1", port)) {
                    HybridHandshake.clientHandshake(s, sKp.getPublic(), List.of("HYBRID"));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            clientFuture.get(5, TimeUnit.SECONDS);
            serverFuture.get(5, TimeUnit.SECONDS);
            exec.shutdown();
        }

        // Verify sequence of steps
        List<String> stepNames = captured.stream().map(HandshakeStepEvent::stepName).toList();
        assertThat(stepNames).containsSubsequence(
                "ClientHello",
                "ServerHello",
                "SignatureCheck",
                "ClientFinished",
                "ServerFinished",
                "ChannelEstablished"
        );

        // Verify sizes match NIST hybrid wire metrics
        HandshakeStepEvent ch = captured.stream().filter(e -> e.stepName().equals("ClientHello")).findFirst().orElseThrow();
        assertThat(ch.messageBytes()).isEqualTo(1356);
        assertThat(ch.direction()).isEqualTo("CLIENT_TO_SERVER");
        assertThat(ch.hex4()).isNotEmpty().isNotEqualTo("null");

        HandshakeStepEvent sh = captured.stream().filter(e -> e.stepName().equals("ServerHello")).findFirst().orElseThrow();
        assertThat(sh.messageBytes()).isEqualTo(4488);
        assertThat(sh.direction()).isEqualTo("SERVER_TO_CLIENT");

        HandshakeStepEvent sig = captured.stream().filter(e -> e.stepName().equals("SignatureCheck")).findFirst().orElseThrow();
        assertThat(sig.messageBytes()).isEqualTo(3309);
        assertThat(sig.outcome()).isEqualTo("OK");

        HandshakeStepEvent cf = captured.stream().filter(e -> e.stepName().equals("ClientFinished")).findFirst().orElseThrow();
        assertThat(cf.messageBytes()).isEqualTo(127);
        assertThat(cf.direction()).isEqualTo("CLIENT_TO_SERVER");

        HandshakeStepEvent sf = captured.stream().filter(e -> e.stepName().equals("ServerFinished")).findFirst().orElseThrow();
        assertThat(sf.messageBytes()).isEqualTo(127);
        assertThat(sf.direction()).isEqualTo("SERVER_TO_CLIENT");

        HandshakeStepEvent est = captured.stream().filter(e -> e.stepName().equals("ChannelEstablished")).findFirst().orElseThrow();
        assertThat(est.outcome()).isEqualTo("SECURE");
    }

    @Test
    @DisplayName("CLASSICAL handshake emits expected ordered steps and classical sizes")
    void classicalHandshakeEmitsOrderedSteps() throws Exception {
        List<HandshakeStepEvent> captured = Collections.synchronizedList(new ArrayList<>());
        HandshakeObserverContext.setGlobalObserver((step, dir, bytes, hex4, outcome, ts) -> {
            captured.add(new HandshakeStepEvent(step, dir, bytes, hex4, outcome, ts));
        });

        KeyPair sKp = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();

        try (ServerSocket server = new ServerSocket(0)) {
            int port = server.getLocalPort();
            ExecutorService exec = Executors.newFixedThreadPool(2);

            Future<?> serverFuture = exec.submit(() -> {
                try (Socket s = server.accept()) {
                    ClassicalHandshake.serverHandshake(s, HandshakeConfig.hardened(), sKp);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            Future<?> clientFuture = exec.submit(() -> {
                try (Socket s = new Socket("127.0.0.1", port)) {
                    ClassicalHandshake.clientHandshake(s, HandshakeConfig.hardened(), sKp.getPublic(), List.of("CLASSICAL"));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            clientFuture.get(5, TimeUnit.SECONDS);
            serverFuture.get(5, TimeUnit.SECONDS);
            exec.shutdown();
        }

        List<String> stepNames = captured.stream().map(HandshakeStepEvent::stepName).toList();
        assertThat(stepNames).containsSubsequence(
                "ClientHello",
                "ServerHello",
                "SignatureCheck",
                "ChannelEstablished"
        );

        HandshakeStepEvent ch = captured.stream().filter(e -> e.stepName().equals("ClientHello")).findFirst().orElseThrow();
        assertThat(ch.messageBytes()).isEqualTo(111);

        HandshakeStepEvent sh = captured.stream().filter(e -> e.stepName().equals("ServerHello")).findFirst().orElseThrow();
        assertThat(sh.messageBytes()).isEqualTo(390);

        HandshakeStepEvent sig = captured.stream().filter(e -> e.stepName().equals("SignatureCheck")).findFirst().orElseThrow();
        assertThat(sig.messageBytes()).isEqualTo(256);
        assertThat(sig.outcome()).isEqualTo("OK");
    }
}
