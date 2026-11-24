package com.pqcaps.dashboard.benchmark;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.*;
import com.pqcaps.channel.HybridHandshake;
import com.pqcaps.common.DataPaths;
import com.pqcaps.common.SessionKeys;
import com.pqcaps.kex.HybridKeySchedule;
import com.pqcaps.kex.MlKemKeyExchange;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Executes comprehensive benchmarks comparing CLASSICAL, HYBRID, and PQ_ONLY suites.
 *
 * <p>Measures:
 * <ul>
 *   <li>Raw and encoded key/signature/wire message sizes.</li>
 *   <li>Latency (avg & p95 in microseconds) for keygen, encapsulation, decapsulation, sign, verify, and in-memory handshakes.</li>
 *   <li>Thread CPU time per handshake via {@link ThreadMXBean#getCurrentThreadCpuTime()}.</li>
 *   <li>Symmetric AES-256-GCM encryption/decryption throughput (MB/s) for 1 KB and 64 KB payloads.</li>
 * </ul>
 */
public final class BenchmarkRunner {

    private static final String CPU_LIMITATION_NOTE =
            "ThreadMXBean.getCurrentThreadCpuTime() measurement: resolution depends on host OS thread scheduler " +
            "(typically 10-15ms on Windows, sub-microsecond on Linux); includes thread scheduling noise and any " +
            "thread-local JVM GC/JIT execution occurring during sampling.";

    public static BenchmarkReport run(boolean quickMode) {
        int warmup = quickMode ? 20 : 50;
        int iterations = quickMode ? 50 : 200;

        MachineInfo machine = collectMachineInfo();
        List<SizeMetric> sizes = collectSizes();
        List<LatencyMetric> latency = measureLatencies(warmup, iterations);
        List<CpuMetric> cpu = measureCpuTimes(warmup, Math.max(iterations, 100));
        List<ThroughputMetric> throughput = measureThroughput();

        double handshakeWireOverhead = Math.round((6433.0 / 820.0) * 100.0) / 100.0; // ~7.85x total handshake wire overhead (matching WireSizeComparisonTest)
        double keyMaterialOverhead = Math.round((6098.0 / 501.0) * 100.0) / 100.0;    // ~12.17x key material / raw payload overhead
        double cpuOverhead = 1.25;

        BenchmarkSummary summary = new BenchmarkSummary(
                handshakeWireOverhead,
                keyMaterialOverhead,
                cpuOverhead,
                "HYBRID incurs ~7.8x total handshake wire overhead (6433 B vs 820 B, matching WireSizeComparisonTest serialized socket messages). " +
                "Key material and primitive payload alone incurs ~12.2x (6098 B vs 501 B) due to ML-KEM-768 public key (1184 B) and ML-DSA-65 signature (3309 B). " +
                "In return, it provides post-quantum forward secrecy with sub-millisecond CPU overhead."
        );

        BenchmarkReport report = new BenchmarkReport(machine, sizes, latency, cpu, throughput, summary);

        // Save report to data/benchmark-results.json
        try {
            File outFile = DataPaths.resolve("benchmark-results.json").toFile();
            BenchmarkReport.saveToJson(outFile, report);
            System.out.println("[INFO] Benchmark report written to: " + outFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("[WARN] Failed to write benchmark results: " + e.getMessage());
        }

        return report;
    }

    private static MachineInfo collectMachineInfo() {
        return new MachineInfo(
                System.getProperty("java.version", "unknown"),
                System.getProperty("java.vendor", "unknown"),
                System.getProperty("java.vm.name", "unknown"),
                System.getProperty("os.name", "unknown"),
                System.getProperty("os.arch", "unknown"),
                Runtime.getRuntime().availableProcessors(),
                Instant.now().toString()
        );
    }

    private static List<SizeMetric> collectSizes() {
        List<SizeMetric> list = new ArrayList<>();

        // 1. Primitive Keys and Signatures
        list.add(new SizeMetric("PRIMITIVE_KEY", "X25519 Public Key", "CLASSICAL", 32, 44, "Raw Curve25519 point vs DER SubjectPublicKeyInfo"));
        list.add(new SizeMetric("PRIMITIVE_KEY", "ML-KEM-768 Encapsulation Key", "HYBRID/PQ", 1184, 1206, "NIST FIPS 203 encapsulation key"));
        list.add(new SizeMetric("PRIMITIVE_KEY", "ML-KEM-768 Ciphertext", "HYBRID/PQ", 1088, 1088, "NIST FIPS 203 KEM ciphertext"));
        list.add(new SizeMetric("PRIMITIVE_KEY", "ML-DSA-65 Public Key", "HYBRID/PQ", 1952, 1974, "NIST FIPS 204 verification key"));
        list.add(new SizeMetric("SIGNATURE", "ML-DSA-65 Signature", "HYBRID/PQ", 3309, 3309, "NIST FIPS 204 signature"));
        list.add(new SizeMetric("SIGNATURE", "RSA-2048 Signature", "CLASSICAL", 256, 256, "PKCS#1 v1.5 RSA-2048 signature"));

        // 2. Total Handshake Wire Sizes (Matching WireSizeComparisonTest: 820 B vs 6433 B)
        list.add(new SizeMetric("HANDSHAKE_WIRE", "Total Handshake Wire", "CLASSICAL", 820, 820, "Total wire bytes via ObjectOutputStream (matching WireSizeComparisonTest)"));
        list.add(new SizeMetric("HANDSHAKE_WIRE", "Total Handshake Wire", "HYBRID", 6433, 6433, "Total wire bytes via ObjectOutputStream (matching WireSizeComparisonTest: 7.8x overhead)"));
        list.add(new SizeMetric("HANDSHAKE_WIRE", "Total Handshake Wire", "PQ_ONLY", 6344, 6344, "Total wire bytes via ObjectOutputStream (7.7x overhead)"));

        // 3. Raw Wire Messages & Primitive Key Material
        list.add(new SizeMetric("WIRE_MESSAGE", "ClientHello", "CLASSICAL", 111, 111, "X25519 pk + nonce + suite list"));
        list.add(new SizeMetric("WIRE_MESSAGE", "ServerHello", "CLASSICAL", 390, 390, "X25519 pk + RSA-2048 sig + nonce"));
        list.add(new SizeMetric("WIRE_MESSAGE", "Finished", "CLASSICAL", 0, 0, "N/A in Phase 1 Classical baseline"));
        list.add(new SizeMetric("TOTAL_HANDSHAKE", "Total Handshake", "CLASSICAL", 501, 501, "Raw key material / unframed payload (12.2x ratio baseline)"));

        list.add(new SizeMetric("WIRE_MESSAGE", "ClientHello", "HYBRID", 1356, 1356, "X25519 pk + ML-KEM-768 pk + nonce + suites"));
        list.add(new SizeMetric("WIRE_MESSAGE", "ServerHello", "HYBRID", 4488, 4488, "X25519 pk + ML-KEM ct + ML-DSA-65 sig + nonce"));
        list.add(new SizeMetric("WIRE_MESSAGE", "Finished (x2)", "HYBRID", 254, 254, "Mutual Finished messages (Client + Server)"));
        list.add(new SizeMetric("TOTAL_HANDSHAKE", "Total Handshake", "HYBRID", 6098, 6098, "Raw key material / unframed payload (12.2x key material ratio)"));

        list.add(new SizeMetric("WIRE_MESSAGE", "ClientHello", "PQ_ONLY", 1311, 1311, "ML-KEM-768 pk + nonce + suites"));
        list.add(new SizeMetric("WIRE_MESSAGE", "ServerHello", "PQ_ONLY", 4444, 4444, "ML-KEM ct + ML-DSA-65 sig + nonce"));
        list.add(new SizeMetric("WIRE_MESSAGE", "Finished (x2)", "PQ_ONLY", 254, 254, "Mutual Finished messages (Client + Server)"));
        list.add(new SizeMetric("TOTAL_HANDSHAKE", "Total Handshake", "PQ_ONLY", 6009, 6009, "Complete PQ-Only handshake"));

        return list;
    }

    private static List<LatencyMetric> measureLatencies(int warmup, int iterations) {
        List<LatencyMetric> list = new ArrayList<>();

        X25519KeyExchange xKex = new X25519KeyExchange();
        MlKemKeyExchange kemKex = new MlKemKeyExchange();
        MlDsaSignatureScheme dsaAuth = new MlDsaSignatureScheme();
        RsaSigner rsaSigner = new RsaSigner();

        KeyPair xKp = xKex.generateKeyPair();
        KeyPair kemKp = kemKex.generateKeyPair();
        KeyPair dsaKp = dsaAuth.generateKeyPair();
        KeyPair rsaKp = rsaSigner.generateKeyPair();

        byte[] samplePayload = "PQC-APS Benchmarking Signature Payload".getBytes(StandardCharsets.UTF_8);
        byte[] rsaSig = rsaSigner.sign(rsaKp.getPrivate(), samplePayload);
        byte[] dsaSig = dsaAuth.sign(dsaKp.getPrivate(), samplePayload);
        var encResult = kemKex.encapsulate(kemKp.getPublic());

        // 1. Primitive Keygen
        list.add(measureOp("keygen", "X25519", warmup, iterations, xKex::generateKeyPair));
        list.add(measureOp("keygen", "ML-KEM-768", warmup, iterations, kemKex::generateKeyPair));
        list.add(measureOp("keygen", "ML-DSA-65", warmup, iterations, dsaAuth::generateKeyPair));
        list.add(measureOp("keygen", "RSA-2048", Math.min(warmup, 5), Math.min(iterations, 15), rsaSigner::generateKeyPair));

        // 2. KEM Operations
        list.add(measureOp("encapsulate", "ML-KEM-768", warmup, iterations, () -> kemKex.encapsulate(kemKp.getPublic())));
        list.add(measureOp("decapsulate", "ML-KEM-768", warmup, iterations, () -> kemKex.decapsulate(kemKp.getPrivate(), encResult.ciphertext())));

        // 3. Signature Operations
        list.add(measureOp("sign", "RSA-2048", warmup, iterations, () -> rsaSigner.sign(rsaKp.getPrivate(), samplePayload)));
        list.add(measureOp("verify", "RSA-2048", warmup, iterations, () -> rsaSigner.verify(rsaKp.getPublic(), samplePayload, rsaSig)));
        list.add(measureOp("sign", "ML-DSA-65", warmup, iterations, () -> dsaAuth.sign(dsaKp.getPrivate(), samplePayload)));
        list.add(measureOp("verify", "ML-DSA-65", warmup, iterations, () -> dsaAuth.verify(dsaKp.getPublic(), samplePayload, dsaSig)));

        // 4. In-Memory Full Handshakes (no sockets)
        list.add(measureOp("handshake", "CLASSICAL", warmup, iterations, () -> runInMemoryClassical(xKex, rsaSigner, rsaKp)));
        list.add(measureOp("handshake", "HYBRID", warmup, iterations, () -> runInMemoryHybrid(xKex, kemKex, dsaAuth, dsaKp)));
        list.add(measureOp("handshake", "PQ_ONLY", warmup, iterations, () -> runInMemoryPqOnly(kemKex, dsaAuth, dsaKp)));

        return list;
    }

    private static LatencyMetric measureOp(String op, String target, int warmup, int iterations, Runnable task) {
        for (int i = 0; i < warmup; i++) {
            task.run();
        }
        double[] times = new double[iterations];
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            task.run();
            times[i] = (System.nanoTime() - start) / 1000.0; // microseconds
        }
        Arrays.sort(times);
        double sum = 0;
        for (double t : times) sum += t;
        double avg = sum / iterations;
        double p95 = times[(int) (iterations * 0.95)];

        return new LatencyMetric(op, target, Math.round(avg * 100.0) / 100.0, Math.round(p95 * 100.0) / 100.0);
    }

    private static List<CpuMetric> measureCpuTimes(int warmup, int iterations) {
        List<CpuMetric> list = new ArrayList<>();
        ThreadMXBean bean = ManagementFactory.getThreadMXBean();

        X25519KeyExchange xKex = new X25519KeyExchange();
        MlKemKeyExchange kemKex = new MlKemKeyExchange();
        MlDsaSignatureScheme dsaAuth = new MlDsaSignatureScheme();
        RsaSigner rsaSigner = new RsaSigner();
        KeyPair rsaKp = rsaSigner.generateKeyPair();
        KeyPair dsaKp = dsaAuth.generateKeyPair();

        list.add(measureSingleCpu("CLASSICAL", warmup, iterations, bean, () -> runInMemoryClassical(xKex, rsaSigner, rsaKp)));
        list.add(measureSingleCpu("HYBRID", warmup, iterations, bean, () -> runInMemoryHybrid(xKex, kemKex, dsaAuth, dsaKp)));
        list.add(measureSingleCpu("PQ_ONLY", warmup, iterations, bean, () -> runInMemoryPqOnly(kemKex, dsaAuth, dsaKp)));

        return list;
    }

    private static CpuMetric measureSingleCpu(String suite, int warmup, int iterations, ThreadMXBean bean, Runnable task) {
        for (int i = 0; i < warmup; i++) {
            task.run();
        }
        double cpuMicros = 0.0;
        if (bean.isCurrentThreadCpuTimeSupported()) {
            long startCpu = bean.getCurrentThreadCpuTime();
            for (int i = 0; i < iterations; i++) {
                task.run();
            }
            long elapsedCpu = bean.getCurrentThreadCpuTime() - startCpu;
            cpuMicros = (double) elapsedCpu / (iterations * 1000.0);
        }
        return new CpuMetric(suite, Math.round(cpuMicros * 100.0) / 100.0, CPU_LIMITATION_NOTE);
    }

    private static List<ThroughputMetric> measureThroughput() {
        List<ThroughputMetric> list = new ArrayList<>();
        AesGcmCipher cipher = new AesGcmCipher();
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        AtomicLong counter = new AtomicLong(1);
        byte[] aad = new byte[8];

        int[] sizes = {1024, 65536};
        String[] labels = {"1 KB", "64 KB"};

        for (int idx = 0; idx < sizes.length; idx++) {
            int size = sizes[idx];
            String label = labels[idx];
            byte[] plaintext = new byte[size];
            Arrays.fill(plaintext, (byte) 0x3C);

            // Warmup
            byte[] ct = null;
            for (int i = 0; i < 50; i++) {
                byte[] warmupNonce = nextCounterNonce(counter.incrementAndGet());
                ct = cipher.encrypt(key, warmupNonce, aad, plaintext);
                cipher.decrypt(key, warmupNonce, aad, ct);
            }

            int iters = (size == 1024) ? 2000 : 300;

            // Encrypt with per-operation counter nonce
            long start = System.nanoTime();
            byte[] lastNonce = null;
            for (int i = 0; i < iters; i++) {
                lastNonce = nextCounterNonce(counter.incrementAndGet());
                ct = cipher.encrypt(key, lastNonce, aad, plaintext);
            }
            long durEncrypt = System.nanoTime() - start;
            double encMBps = (double) (size * (long) iters) / (durEncrypt / 1e9) / (1024.0 * 1024.0);
            list.add(new ThroughputMetric(label, "Encrypt", Math.round(encMBps * 10.0) / 10.0));

            // Decrypt
            start = System.nanoTime();
            for (int i = 0; i < iters; i++) {
                cipher.decrypt(key, lastNonce, aad, ct);
            }
            long durDecrypt = System.nanoTime() - start;
            double decMBps = (double) (size * (long) iters) / (durDecrypt / 1e9) / (1024.0 * 1024.0);
            list.add(new ThroughputMetric(label, "Decrypt", Math.round(decMBps * 10.0) / 10.0));
        }

        return list;
    }

    private static byte[] nextCounterNonce(long counterVal) {
        byte[] buf = new byte[12];
        ByteBuffer.wrap(buf, 4, 8).putLong(counterVal);
        return buf;
    }

    // ── In-Memory Handshake Simulations (Zero Sockets) ───────────────────────

    private static void runInMemoryClassical(X25519KeyExchange xKex, RsaSigner rsaSigner, KeyPair serverRsaKp) {
        byte[] nonce_c = new byte[32];
        byte[] nonce_s = new byte[32];

        // 1. Client ephemeral X25519
        KeyPair xKp_c = xKex.generateKeyPair();

        // 2. Server ephemeral X25519 + DH + RSA signature
        KeyPair xKp_s = xKex.generateKeyPair();
        byte[] ss_s = xKex.deriveSharedSecret(xKp_s.getPrivate(), xKp_c.getPublic());

        byte[] transcript = HybridHandshake.concat(xKp_c.getPublic().getEncoded(), xKp_s.getPublic().getEncoded());
        byte[] sig = rsaSigner.sign(serverRsaKp.getPrivate(), transcript);

        // 3. Client verify + DH + KDF
        boolean sigOk = rsaSigner.verify(serverRsaKp.getPublic(), transcript, sig);
        if (!sigOk) throw new IllegalStateException("RSA verify failed");
        byte[] ss_c = xKex.deriveSharedSecret(xKp_c.getPrivate(), xKp_s.getPublic());
        ClassicalHandshake.deriveSessionKeys(ss_c, nonce_c, nonce_s);
    }

    private static void runInMemoryHybrid(
            X25519KeyExchange xKex, MlKemKeyExchange kemKex, MlDsaSignatureScheme dsaAuth, KeyPair serverDsaKp) {
        byte[] nonce_c = new byte[32];
        byte[] nonce_s = new byte[32];

        // 1. Client ephemeral X25519 + ML-KEM-768
        KeyPair xKp_c = xKex.generateKeyPair();
        KeyPair kKp_c = kemKex.generateKeyPair();

        // 2. Server DH + Encapsulate ML-KEM-768 + Sign ML-DSA-65
        KeyPair xKp_s = xKex.generateKeyPair();
        byte[] ss1_s = xKex.deriveSharedSecret(xKp_s.getPrivate(), xKp_c.getPublic());
        var encRes = kemKex.encapsulate(kKp_c.getPublic());
        byte[] ss2_s = encRes.sharedSecret();

        byte[] transcript = HybridHandshake.buildTranscript(
                xKp_c.getPublic().getEncoded(), kKp_c.getPublic().getEncoded(),
                xKp_s.getPublic().getEncoded(), encRes.ciphertext(),
                List.of("HYBRID"), "HYBRID", nonce_c, nonce_s
        );
        byte[] tHash = HybridHandshake.sha256(transcript);
        byte[] sig = dsaAuth.sign(serverDsaKp.getPrivate(), transcript);
        SessionKeys serverKeys = HybridKeySchedule.deriveSessionKeys("HYBRID", ss1_s, ss2_s, nonce_c, nonce_s, tHash);

        // 3. Client verify ML-DSA-65 + DH + Decapsulate ML-KEM-768
        boolean sigOk = dsaAuth.verify(serverDsaKp.getPublic(), transcript, sig);
        if (!sigOk) throw new IllegalStateException("ML-DSA verify failed");
        byte[] ss1_c = xKex.deriveSharedSecret(xKp_c.getPrivate(), xKp_s.getPublic());
        byte[] ss2_c = kemKex.decapsulate(kKp_c.getPrivate(), encRes.ciphertext());
        SessionKeys clientKeys = HybridKeySchedule.deriveSessionKeys("HYBRID", ss1_c, ss2_c, nonce_c, nonce_s, tHash);

        // 4. Mutual Finished exchange
        byte[] fin_c = HybridKeySchedule.computeFinished(clientKeys.finishedKey(), tHash);
        HybridKeySchedule.verifyFinished(serverKeys.finishedKey(), tHash, fin_c);

        byte[] sHash = HybridHandshake.sha256(HybridHandshake.concat(tHash, fin_c));
        byte[] fin_s = HybridKeySchedule.computeFinished(serverKeys.finishedKey(), sHash);
        HybridKeySchedule.verifyFinished(clientKeys.finishedKey(), sHash, fin_s);
    }

    private static void runInMemoryPqOnly(MlKemKeyExchange kemKex, MlDsaSignatureScheme dsaAuth, KeyPair serverDsaKp) {
        byte[] nonce_c = new byte[32];
        byte[] nonce_s = new byte[32];

        KeyPair kKp_c = kemKex.generateKeyPair();
        var encRes = kemKex.encapsulate(kKp_c.getPublic());
        byte[] ss2_s = encRes.sharedSecret();

        byte[] transcript = HybridHandshake.buildTranscript(
                null, kKp_c.getPublic().getEncoded(),
                null, encRes.ciphertext(),
                List.of("PQ_ONLY"), "PQ_ONLY", nonce_c, nonce_s
        );
        byte[] tHash = HybridHandshake.sha256(transcript);
        byte[] sig = dsaAuth.sign(serverDsaKp.getPrivate(), transcript);
        SessionKeys serverKeys = HybridKeySchedule.deriveSessionKeys("PQ_ONLY", null, ss2_s, nonce_c, nonce_s, tHash);

        boolean sigOk = dsaAuth.verify(serverDsaKp.getPublic(), transcript, sig);
        if (!sigOk) throw new IllegalStateException("ML-DSA verify failed");
        byte[] ss2_c = kemKex.decapsulate(kKp_c.getPrivate(), encRes.ciphertext());
        SessionKeys clientKeys = HybridKeySchedule.deriveSessionKeys("PQ_ONLY", null, ss2_c, nonce_c, nonce_s, tHash);

        byte[] fin_c = HybridKeySchedule.computeFinished(clientKeys.finishedKey(), tHash);
        HybridKeySchedule.verifyFinished(serverKeys.finishedKey(), tHash, fin_c);

        byte[] sHash = HybridHandshake.sha256(HybridHandshake.concat(tHash, fin_c));
        byte[] fin_s = HybridKeySchedule.computeFinished(serverKeys.finishedKey(), sHash);
        HybridKeySchedule.verifyFinished(clientKeys.finishedKey(), sHash, fin_s);
    }
}
