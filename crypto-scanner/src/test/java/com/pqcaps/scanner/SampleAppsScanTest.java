package com.pqcaps.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Sample Applications Comparative Scan Tests")
class SampleAppsScanTest {

    private final SourceScanner scanner = new SourceScanner();

    @Test
    @DisplayName("Compare vulnerable-app vs migrated-app: vulnerable scores worse, migrated gets Grade A and 100% PQC readiness")
    void testCompareSampleApps() throws Exception {
        Path vulnPath = Path.of("../samples/vulnerable-app");
        if (!vulnPath.toFile().exists()) {
            vulnPath = Path.of("samples/vulnerable-app");
        }
        assertThat(vulnPath.toFile()).as("samples/vulnerable-app directory exists").exists();

        Path migratedPath = Path.of("../samples/migrated-app");
        if (!migratedPath.toFile().exists()) {
            migratedPath = Path.of("samples/migrated-app");
        }
        assertThat(migratedPath.toFile()).as("samples/migrated-app directory exists").exists();

        // 1. Scan Vulnerable App
        List<ScanFinding> vulnFindings = scanner.scanDirectory(vulnPath);
        ScanSummary vulnSummary = RiskScoreCalculator.createSummary(vulnFindings);

        assertThat(vulnFindings).isNotEmpty();
        assertThat(vulnSummary.overallScore())
                .as("Vulnerable app should have high overall risk score")
                .isGreaterThanOrEqualTo(70);
        assertThat(List.of("D", "F"))
                .as("Vulnerable app should receive failing or poor grade")
                .contains(vulnSummary.grade());
        assertThat(vulnSummary.quantumReadiness())
                .as("Vulnerable app should have 0% quantum readiness")
                .isEqualTo(0.0);

        // Verify secrets are redacted in findings
        for (ScanFinding f : vulnFindings) {
            assertThat(f.redactedSnippet())
                    .doesNotContain("DUMMY_SECRET_KEY_1234567890_EXAMP")
                    .doesNotContain("DUMMY_TOKEN_ABCDEF1234567890_EXAMP")
                    .doesNotContain("DUMMY_PASSWORD_XYZ987654321_ADMIN");
        }

        // 2. Scan Migrated App
        List<ScanFinding> migratedFindings = scanner.scanDirectory(migratedPath);
        ScanSummary migratedSummary = RiskScoreCalculator.createSummary(migratedFindings);

        assertThat(migratedSummary.overallScore())
                .as("Migrated app should have zero or low risk score")
                .isLessThanOrEqualTo(20);
        assertThat(migratedSummary.grade())
                .as("Migrated app should achieve Grade A")
                .isEqualTo("A");
        assertThat(migratedSummary.quantumReadiness())
                .as("Migrated app should achieve 100% quantum readiness")
                .isEqualTo(100.0);

        // PQC-READY findings must be present
        boolean hasPqc = migratedFindings.stream().anyMatch(f -> "RULE-PQC-READY".equals(f.ruleId()));
        assertThat(hasPqc).as("Migrated app contains PQC-READY primitives").isTrue();

        // 3. Vulnerable app scores strictly worse than migrated app
        assertThat(vulnSummary.overallScore()).isGreaterThan(migratedSummary.overallScore());
    }
}
