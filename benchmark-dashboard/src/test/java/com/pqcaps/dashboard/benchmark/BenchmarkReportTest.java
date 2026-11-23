package com.pqcaps.dashboard.benchmark;

import com.pqcaps.common.DataPaths;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JMH Benchmark Report Verification")
class BenchmarkReportTest {

    @Test
    @DisplayName("Benchmark runner generates valid report matching NIST FIPS 203 / 204 size constants")
    void benchmarkReportMatchesNistConstants() {
        BenchmarkReport report = BenchmarkRunner.run(true);

        assertThat(report).isNotNull();
        assertThat(report.machine()).isNotNull();
        assertThat(report.machine().jdkVersion()).isNotBlank();
        assertThat(report.machine().cpuCores()).isPositive();

        // Verify NIST raw and encoded sizes
        List<SizeMetric> sizes = report.sizes();
        assertThat(sizes).isNotEmpty();

        assertSize(sizes, "X25519 Public Key", 32, 44);
        assertSize(sizes, "ML-KEM-768 Encapsulation Key", 1184, 1206);
        assertSize(sizes, "ML-KEM-768 Ciphertext", 1088, 1088);
        assertSize(sizes, "ML-DSA-65 Public Key", 1952, 1974);
        assertSize(sizes, "ML-DSA-65 Signature", 3309, 3309);
        assertSize(sizes, "RSA-2048 Signature", 256, 256);

        // Verify Handshake Wire Sizes
        assertSize(sizes, "ClientHello", "CLASSICAL", 111);
        assertSize(sizes, "ServerHello", "CLASSICAL", 390);
        assertSize(sizes, "Total Handshake", "CLASSICAL", 501);

        assertSize(sizes, "ClientHello", "HYBRID", 1356);
        assertSize(sizes, "ServerHello", "HYBRID", 4488);
        assertSize(sizes, "Finished (x2)", "HYBRID", 254);
        assertSize(sizes, "Total Handshake", "HYBRID", 6098);

        assertSize(sizes, "ClientHello", "PQ_ONLY", 1311);
        assertSize(sizes, "ServerHello", "PQ_ONLY", 4444);
        assertSize(sizes, "Finished (x2)", "PQ_ONLY", 254);
        assertSize(sizes, "Total Handshake", "PQ_ONLY", 6009);

        // Verify output file exists
        File jsonFile = DataPaths.resolve("benchmark-results.json").toFile();
        assertThat(jsonFile).exists();

        // Verify throughput metrics present
        assertThat(report.throughput()).isNotEmpty();
        assertThat(report.summary().hybridWireOverheadRatio()).isGreaterThan(10.0);
    }

    private void assertSize(List<SizeMetric> sizes, String item, int expectedRaw, int expectedEnc) {
        SizeMetric m = sizes.stream()
                .filter(s -> s.item().equalsIgnoreCase(item))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing size metric: " + item));
        assertThat(m.rawBytes()).as("Raw bytes for " + item).isEqualTo(expectedRaw);
        assertThat(m.encodedBytes()).as("Encoded bytes for " + item).isEqualTo(expectedEnc);
    }

    private void assertSize(List<SizeMetric> sizes, String item, String suite, int expectedRaw) {
        SizeMetric m = sizes.stream()
                .filter(s -> s.item().equalsIgnoreCase(item) && s.suite().equalsIgnoreCase(suite))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing wire metric: " + item + " for " + suite));
        assertThat(m.rawBytes()).as("Raw bytes for " + item + " (" + suite + ")").isEqualTo(expectedRaw);
    }
}
