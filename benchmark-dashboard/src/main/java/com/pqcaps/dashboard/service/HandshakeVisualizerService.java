package com.pqcaps.dashboard.service;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.ClassicalHandshake;
import com.pqcaps.channel.HybridHandshake;
import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.HandshakeObserver;
import com.pqcaps.common.HandshakeObserverContext;
import com.pqcaps.common.HandshakeStepEvent;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class HandshakeVisualizerService {

    public record HandshakeVisualizerResult(
            String suite,
            List<HandshakeStepEvent> steps,
            int totalWireBytes,
            long elapsedNanos,
            double elapsedMillis,
            String outcome
    ) {
        public String getSuite() { return suite; }
        public List<HandshakeStepEvent> getSteps() { return steps; }
        public int getTotalWireBytes() { return totalWireBytes; }
        public long getElapsedNanos() { return elapsedNanos; }
        public double getElapsedMillis() { return elapsedMillis; }
        public String getOutcome() { return outcome; }
    }

    private final ReentrantLock runLock = new ReentrantLock();
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public HandshakeVisualizerResult executeHandshake(String suite) {
        if (!runLock.tryLock()) {
            throw new IllegalStateException("A handshake simulation is already in progress. Please wait.");
        }
        try {
            return doRunHandshake(suite, null);
        } finally {
            runLock.unlock();
        }
    }

    public void streamHandshake(String suite, SseEmitter emitter) {
        if (suite == null || !List.of("CLASSICAL", "HYBRID", "PQ_ONLY").contains(suite.toUpperCase())) {
            try {
                emitter.send(SseEmitter.event().name("error").data("Invalid suite: " + suite));
                emitter.complete();
            } catch (Exception ignored) {}
            return;
        }

        executor.submit(() -> {
            if (!runLock.tryLock()) {
                try {
                    emitter.send(SseEmitter.event().name("error").data("Another handshake run is currently active."));
                    emitter.complete();
                } catch (Exception ignored) {}
                return;
            }
            try {
                doRunHandshake(suite.toUpperCase(), emitter);
            } catch (Exception e) {
                try {
                    emitter.send(SseEmitter.event().name("error").data("Handshake failed: " + e.getMessage()));
                } catch (Exception ignored) {}
            } finally {
                runLock.unlock();
                emitter.complete();
            }
        });
    }

    private HandshakeVisualizerResult doRunHandshake(String suite, SseEmitter emitter) {
        String suiteUpper = suite.toUpperCase();
        if (!List.of("CLASSICAL", "HYBRID", "PQ_ONLY").contains(suiteUpper)) {
            throw new IllegalArgumentException("Invalid suite: '" + suite + "'. Allowed: CLASSICAL, HYBRID, PQ_ONLY");
        }

        List<HandshakeStepEvent> steps = Collections.synchronizedList(new ArrayList<>());
        HandshakeObserver observer = (stepName, direction, messageBytes, hex4, outcome, timestamp) -> {
            HandshakeStepEvent event = new HandshakeStepEvent(stepName, direction, messageBytes, hex4, outcome, timestamp);
            steps.add(event);
            if (emitter != null) {
                try {
                    emitter.send(SseEmitter.event().name("step").data(event));
                    // Brief delay so animation is clearly visible in presentation/viva
                    Thread.sleep(180);
                } catch (Exception ignored) {}
            }
        };

        long startTime = System.nanoTime();
        HandshakeObserverContext.setGlobalObserver(observer);
        try {
            if ("CLASSICAL".equals(suiteUpper)) {
                runClassicalHandshake();
            } else {
                runHybridOrPqHandshake(suiteUpper);
            }
        } catch (Exception e) {
            throw new RuntimeException("Handshake failed: " + e.getMessage(), e);
        } finally {
            HandshakeObserverContext.setGlobalObserver(HandshakeObserver.NOOP);
        }
        long elapsedNanos = System.nanoTime() - startTime;
        double elapsedMillis = Math.round((elapsedNanos / 1_000_000.0) * 100.0) / 100.0;

        int totalBytes = steps.stream()
                .filter(s -> "CLIENT_TO_SERVER".equals(s.direction()) || "SERVER_TO_CLIENT".equals(s.direction()))
                .mapToInt(HandshakeStepEvent::messageBytes)
                .sum();

        HandshakeVisualizerResult result = new HandshakeVisualizerResult(
                suiteUpper, steps, totalBytes, elapsedNanos, elapsedMillis, "SECURE"
        );

        if (emitter != null) {
            try {
                emitter.send(SseEmitter.event().name("complete").data(result));
            } catch (Exception ignored) {}
        }

        return result;
    }

    private void runClassicalHandshake() throws Exception {
        KeyPair serverKp = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            int port = server.getLocalPort();
            Future<?> serverFuture = executor.submit(() -> {
                try (Socket s = server.accept()) {
                    ClassicalHandshake.serverHandshake(s, HandshakeConfig.hardened(), serverKp);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            Future<?> clientFuture = executor.submit(() -> {
                try (Socket s = new Socket("127.0.0.1", port)) {
                    ClassicalHandshake.clientHandshake(s, HandshakeConfig.hardened(), serverKp.getPublic(), List.of("CLASSICAL"));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            clientFuture.get(5, TimeUnit.SECONDS);
            serverFuture.get(5, TimeUnit.SECONDS);
        }
    }

    private void runHybridOrPqHandshake(String suite) throws Exception {
        MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();
        KeyPair sKp = dsa.generateKeyPair();
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            int port = server.getLocalPort();
            Future<?> serverFuture = executor.submit(() -> {
                try (Socket s = server.accept()) {
                    HybridHandshake.serverHandshake(s, sKp.getPrivate(), false);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            Future<?> clientFuture = executor.submit(() -> {
                try (Socket s = new Socket("127.0.0.1", port)) {
                    HybridHandshake.clientHandshake(s, sKp.getPublic(), List.of(suite));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            clientFuture.get(5, TimeUnit.SECONDS);
            serverFuture.get(5, TimeUnit.SECONDS);
        }
    }
}
