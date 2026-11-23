package com.pqcaps.attack;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Prevents timing side-channel attacks on cryptographic comparison operations.
 *
 * <p>Standard early-exit comparisons terminate at the first non-matching byte,
 * leaking information about prefix matches through execution time variations.
 *
 * <p>{@code TimingGuard} guarantees constant-time evaluation using
 * {@link MessageDigest#isEqual(byte[], byte[])}.
 */
public final class TimingGuard {

    private final EventLog eventLog;

    public TimingGuard() {
        this(EventLog.getInstance());
    }

    public TimingGuard(EventLog eventLog) {
        this.eventLog = eventLog;
    }

    /**
     * Performs a constant-time comparison of two byte arrays.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Hand-written naive early-exit byte comparison loop.
     * Unlike {@link Arrays#equals}, this explicit loop avoids JIT SIMD/AVX vectorization
     * that masks byte-level early termination.
     */
    public static boolean naiveEarlyExitEquals(byte[] a, byte[] b) {
        if (a == b) return true;
        if (a == null || b == null || a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validates a cryptographic tag/MAC in constant time, emitting an event if tampered.
     */
    public boolean verifyTag(byte[] expected, byte[] actual, String component, String suite) {
        boolean valid = constantTimeEquals(expected, actual);
        if (!valid) {
            eventLog.record(
                    DetectionEvent.AttackType.TIMING,
                    DetectionEvent.Severity.HIGH,
                    component,
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    "Cryptographic authentication tag mismatch detected via constant-time verification"
            );
        }
        return valid;
    }

    /**
     * Default benchmark demo using 4096-byte arrays, 200k warmup, 2M iterations across 5 trials.
     */
    public static void runTimingBenchmarkDemo() {
        runTimingBenchmarkDemo(200_000, 2_000_000, 5);
    }

    /**
     * Benchmark demo with custom iteration count for testing/diagnostics.
     */
    public static void runTimingBenchmarkDemo(int iterations) {
        int warmup = Math.min(200_000, Math.max(1_000, iterations / 5));
        int trials = iterations >= 1_000_000 ? 5 : 1;
        runTimingBenchmarkDemo(warmup, iterations, trials);
    }

    /**
     * Demonstrates timing side-channel differences using 4096-byte arrays and computes
     * verdicts directly from measured median execution times.
     */
    public static void runTimingBenchmarkDemo(int warmup, int iterations, int trials) {
        final int arrayLen = 4096;
        byte[] expected = new byte[arrayLen];
        byte[] mismatchFirst = new byte[arrayLen];
        byte[] mismatchLast = new byte[arrayLen];

        Arrays.fill(expected, (byte) 0xAA);
        Arrays.fill(mismatchFirst, (byte) 0xAA);
        Arrays.fill(mismatchLast, (byte) 0xAA);

        mismatchFirst[0] ^= 0x01;              // Mismatch at byte 0
        mismatchLast[arrayLen - 1] ^= 0x01;    // Mismatch at byte 4095

        // 1. Warmup JIT compiler
        boolean sink = false;
        for (int i = 0; i < warmup; i++) {
            sink ^= naiveEarlyExitEquals(expected, mismatchFirst);
            sink ^= naiveEarlyExitEquals(expected, mismatchLast);
            sink ^= constantTimeEquals(expected, mismatchFirst);
            sink ^= constantTimeEquals(expected, mismatchLast);
        }

        double[] naiveFirstTimes = new double[trials];
        double[] naiveLastTimes = new double[trials];
        double[] constFirstTimes = new double[trials];
        double[] constLastTimes = new double[trials];

        // 2. Measure across trials
        for (int t = 0; t < trials; t++) {
            // Naive: mismatch at byte 0
            long start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                sink ^= naiveEarlyExitEquals(expected, mismatchFirst);
            }
            naiveFirstTimes[t] = (double) (System.nanoTime() - start) / iterations;

            // Naive: mismatch at byte 4095
            start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                sink ^= naiveEarlyExitEquals(expected, mismatchLast);
            }
            naiveLastTimes[t] = (double) (System.nanoTime() - start) / iterations;

            // Constant-time: mismatch at byte 0
            start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                sink ^= constantTimeEquals(expected, mismatchFirst);
            }
            constFirstTimes[t] = (double) (System.nanoTime() - start) / iterations;

            // Constant-time: mismatch at byte 4095
            start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                sink ^= constantTimeEquals(expected, mismatchLast);
            }
            constLastTimes[t] = (double) (System.nanoTime() - start) / iterations;
        }

        // Avoid dead-code elimination
        if (sink) {
            System.out.print("");
        }

        // 3. Compute medians
        Arrays.sort(naiveFirstTimes);
        Arrays.sort(naiveLastTimes);
        Arrays.sort(constFirstTimes);
        Arrays.sort(constLastTimes);

        double naiveFirstMedian = naiveFirstTimes[trials / 2];
        double naiveLastMedian = naiveLastTimes[trials / 2];
        double constFirstMedian = constFirstTimes[trials / 2];
        double constLastMedian = constLastTimes[trials / 2];

        // 4. Compute verdicts dynamically from measurements
        double naiveRatio = naiveLastMedian / Math.max(1e-9, naiveFirstMedian);
        double constRatio = constLastMedian / Math.max(1e-9, constFirstMedian);

        String naiveVerdict = (naiveRatio > 2.0)
                ? String.format("LEAK VISIBLE (ratio: %.1fx difference between byte 0 and 4095)", naiveRatio)
                : String.format("NO SIGNIFICANT LEAK DETECTED (ratio: %.1fx difference)", naiveRatio);

        String constVerdict = (constRatio >= 0.7 && constRatio <= 1.4)
                ? String.format("CONSTANT-TIME VERIFIED (ratio: %.2fx, delta < 40%%)", constRatio)
                : String.format("RATIO: %.2fx", constRatio);

        System.out.println("─".repeat(78));
        System.out.printf("  TIMING SIDE-CHANNEL BENCHMARK (Array: 4096 B, %d iters x %d trials)%n", iterations, trials);
        System.out.println("─".repeat(78));
        System.out.printf("  Naive early-exit (mismatch @ byte 0)    : %8.2f ns/op%n", naiveFirstMedian);
        System.out.printf("  Naive early-exit (mismatch @ byte 4095) : %8.2f ns/op  <-- %s%n", naiveLastMedian, naiveVerdict);
        System.out.printf("  Constant-time    (mismatch @ byte 0)    : %8.2f ns/op%n", constFirstMedian);
        System.out.printf("  Constant-time    (mismatch @ byte 4095) : %8.2f ns/op  <-- %s%n", constLastMedian, constVerdict);
        System.out.println("─".repeat(78));
    }
}
