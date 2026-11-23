package com.pqcaps.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Risk Score Calculator Tests")
class RiskScoreCalculatorTest {

    @Test
    @DisplayName("Verify base scores by category")
    void testBaseScores() {
        assertThat(RiskScoreCalculator.computeRiskScore("CIPHER_BROKEN", 0, 10)).isEqualTo(95);
        assertThat(RiskScoreCalculator.computeRiskScore("SECRET_HARDCODED", 0, 10)).isEqualTo(90);
        assertThat(RiskScoreCalculator.computeRiskScore("KEY_EXCHANGE_QV", 0, 10)).isEqualTo(85);
        assertThat(RiskScoreCalculator.computeRiskScore("RNG_WEAK", 0, 10)).isEqualTo(80);
        assertThat(RiskScoreCalculator.computeRiskScore("TLS_LEGACY", 0, 10)).isEqualTo(80);
        assertThat(RiskScoreCalculator.computeRiskScore("HASH_BROKEN", 0, 10)).isEqualTo(70);
        assertThat(RiskScoreCalculator.computeRiskScore("SIGNATURE_QV", 0, 10)).isEqualTo(60);
        assertThat(RiskScoreCalculator.computeRiskScore("SYMMETRIC_INFO", 0, 10)).isEqualTo(20);
        assertThat(RiskScoreCalculator.computeRiskScore("PQC_READY", 0, 10)).isEqualTo(0);
    }

    @Test
    @DisplayName("Verify dataLifetimeYears multiplier (1.2x capped at 100 for key-exchange / encryption)")
    void testDataLifetimeMultiplier() {
        // Normal 10 years: base 85
        int normal = RiskScoreCalculator.computeRiskScore("KEY_EXCHANGE_QV", 85, 10);
        assertThat(normal).isEqualTo(85);

        // Long lifetime 15 years: 85 * 1.2 = 102 -> capped at 100
        int longTerm = RiskScoreCalculator.computeRiskScore("KEY_EXCHANGE_QV", 85, 15);
        assertThat(longTerm).isEqualTo(100);

        // Hashes should not be multiplied by lifetime
        int hashScore = RiskScoreCalculator.computeRiskScore("HASH_BROKEN", 70, 20);
        assertThat(hashScore).isEqualTo(70);
    }

    @Test
    @DisplayName("Verify severity classification from score")
    void testScoreToSeverity() {
        assertThat(RiskScoreCalculator.scoreToSeverity(95, "CIPHER_BROKEN")).isEqualTo("CRITICAL");
        assertThat(RiskScoreCalculator.scoreToSeverity(90, "SECRET_HARDCODED")).isEqualTo("CRITICAL");
        assertThat(RiskScoreCalculator.scoreToSeverity(85, "KEY_EXCHANGE_QV")).isEqualTo("HIGH");
        assertThat(RiskScoreCalculator.scoreToSeverity(70, "HASH_BROKEN")).isEqualTo("HIGH");
        assertThat(RiskScoreCalculator.scoreToSeverity(60, "SIGNATURE_QV")).isEqualTo("MEDIUM");
        assertThat(RiskScoreCalculator.scoreToSeverity(20, "OTHER")).isEqualTo("LOW");
        assertThat(RiskScoreCalculator.scoreToSeverity(20, "SYMMETRIC_INFO")).isEqualTo("INFO");
        assertThat(RiskScoreCalculator.scoreToSeverity(0, "PQC_READY")).isEqualTo("INFO");
    }

    @Test
    @DisplayName("Verify project overallScore formula and grade boundaries")
    void testOverallScoreAndGrade() {
        ScanFinding f1 = createFinding(95, "CIPHER_BROKEN", false);
        ScanFinding f2 = createFinding(85, "KEY_EXCHANGE_QV", true);
        ScanFinding f3 = createFinding(70, "HASH_BROKEN", false);

        // max = 95, avg = (95+85+70)/3 = 83.333
        // overall = 0.6 * 95 + 0.4 * 83.333 = 57 + 33.33 = 90
        int score = RiskScoreCalculator.computeOverallScore(List.of(f1, f2, f3));
        assertThat(score).isEqualTo(90);
        assertThat(RiskScoreCalculator.scoreToGrade(score)).isEqualTo("F");

        // Grade boundaries
        assertThat(RiskScoreCalculator.scoreToGrade(15)).isEqualTo("A");
        assertThat(RiskScoreCalculator.scoreToGrade(20)).isEqualTo("A");
        assertThat(RiskScoreCalculator.scoreToGrade(25)).isEqualTo("B");
        assertThat(RiskScoreCalculator.scoreToGrade(40)).isEqualTo("B");
        assertThat(RiskScoreCalculator.scoreToGrade(55)).isEqualTo("C");
        assertThat(RiskScoreCalculator.scoreToGrade(60)).isEqualTo("C");
        assertThat(RiskScoreCalculator.scoreToGrade(75)).isEqualTo("D");
        assertThat(RiskScoreCalculator.scoreToGrade(80)).isEqualTo("D");
        assertThat(RiskScoreCalculator.scoreToGrade(85)).isEqualTo("F");
    }

    @Test
    @DisplayName("Verify Quantum Readiness calculation")
    void testQuantumReadiness() {
        ScanFinding qv1 = createFinding(85, "KEY_EXCHANGE_QV", true);
        ScanFinding qv2 = createFinding(85, "KEY_EXCHANGE_QV", true);
        ScanFinding pqc1 = createFinding(0, "PQC_READY", false);

        // 1 PQC out of (1 PQC + 2 QV) = 1/3 = 33.3%
        double readiness = RiskScoreCalculator.computeQuantumReadiness(List.of(qv1, qv2, pqc1));
        assertThat(readiness).isEqualTo(33.3);

        // 100% when all public key algorithms are PQC
        double allPqc = RiskScoreCalculator.computeQuantumReadiness(List.of(pqc1));
        assertThat(allPqc).isEqualTo(100.0);
    }

    private ScanFinding createFinding(int score, String category, boolean qv) {
        return new ScanFinding("id", "rule", category, "file.java", 1, "snippet", "algo", qv,
                RiskScoreCalculator.scoreToSeverity(score, category), score, "exp", "rec", "target");
    }
}
