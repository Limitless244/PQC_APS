package com.pqcaps.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Scan Report JSON Serialization Tests")
class ScanReportJsonTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Verify ScanReport serializes to and deserializes from JSON")
    void testJsonRoundTrip() throws IOException {
        ScanFinding finding = new ScanFinding(
                "f-1234",
                "RULE-RSA",
                "KEY_EXCHANGE_QV",
                "src/Crypto.java",
                42,
                "KeyPairGenerator.getInstance(\"RSA\");",
                "RSA-2048",
                true,
                "HIGH",
                85,
                "Vulnerable to Shor's algorithm",
                "Migrate to ML-KEM-768",
                "ML-KEM-768"
        );

        ScanSummary summary = new ScanSummary(
                1,
                Map.of("HIGH", 1),
                85,
                "F",
                0.0
        );

        ScanReport report = new ScanReport(
                "scan-999",
                "Directory: /test",
                "2026-11-23T12:00:00Z",
                summary,
                List.of(finding)
        );

        File jsonFile = tempDir.resolve("test-report.json").toFile();
        ScanReport.saveToJson(jsonFile, report);

        assertThat(jsonFile).exists().isNotEmpty();

        ScanReport loaded = ScanReport.loadFromJson(jsonFile);
        assertThat(loaded.scanId()).isEqualTo("scan-999");
        assertThat(loaded.findings()).hasSize(1);
        assertThat(loaded.findings().get(0).algorithm()).isEqualTo("RSA-2048");
        assertThat(loaded.summary().grade()).isEqualTo("F");
    }
}
