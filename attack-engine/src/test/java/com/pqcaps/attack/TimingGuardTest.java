package com.pqcaps.attack;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class TimingGuardTest {

    @Test
    void constantTimeEqualsReturnsTrueForIdenticalArrays() {
        byte[] a = "CryptographicTagConstantTime1234".getBytes();
        byte[] b = "CryptographicTagConstantTime1234".getBytes();

        assertThat(TimingGuard.constantTimeEquals(a, b)).isTrue();
    }

    @Test
    void constantTimeEqualsReturnsFalseForDifferingArrays() {
        byte[] a = "CryptographicTagConstantTime1234".getBytes();
        byte[] b = "CryptographicTagConstantTime1235".getBytes();

        assertThat(TimingGuard.constantTimeEquals(a, b)).isFalse();
    }

    @Test
    void constantTimeEqualsHandlesNullsAndLengthMismatches() {
        byte[] a = new byte[16];
        byte[] b = new byte[32];

        assertThat(TimingGuard.constantTimeEquals(a, b)).isFalse();
        assertThat(TimingGuard.constantTimeEquals(a, null)).isFalse();
        assertThat(TimingGuard.constantTimeEquals(null, null)).isTrue();
    }

    @Test
    void naiveEarlyExitEqualsCorrectness() {
        byte[] a = new byte[4096];
        byte[] b = new byte[4096];
        Arrays.fill(a, (byte) 0x55);
        Arrays.fill(b, (byte) 0x55);

        assertThat(TimingGuard.naiveEarlyExitEquals(a, b)).isTrue();

        // Mismatch at byte 0
        b[0] ^= 0x01;
        assertThat(TimingGuard.naiveEarlyExitEquals(a, b)).isFalse();

        // Mismatch at byte 4095
        b[0] ^= 0x01;
        b[4095] ^= 0x01;
        assertThat(TimingGuard.naiveEarlyExitEquals(a, b)).isFalse();

        // Length mismatch and nulls
        assertThat(TimingGuard.naiveEarlyExitEquals(a, new byte[2048])).isFalse();
        assertThat(TimingGuard.naiveEarlyExitEquals(a, null)).isFalse();
        assertThat(TimingGuard.naiveEarlyExitEquals(null, null)).isTrue();
    }

    @Test
    void timingBenchmarkDemoExecutesCleanly() {
        // Runs benchmark demo with small iterations to ensure code executes without exceptions
        TimingGuard.runTimingBenchmarkDemo(2_000);
    }
}
