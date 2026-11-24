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
    @DisplayName("Verify exponential score formula round(100 * (1 - exp(-points/60))) and grade bands")
    void testOverallScoreAndGrade() {
        ScanFinding f1 = createFinding(95, "CIPHER_BROKEN", false);   // CRITICAL (25)
        ScanFinding f2 = createFinding(85, "KEY_EXCHANGE_QV", true);  // HIGH (10)
        ScanFinding f3 = createFinding(70, "HASH_BROKEN", false);     // HIGH (10)

        // points = 25*1 + 10*2 = 45 -> score = round(100 * (1 - exp(-45/60))) = 53 -> Grade D (51-75)
        int points = RiskScoreCalculator.computeRiskPoints(List.of(f1, f2, f3));
        assertThat(points).isEqualTo(45);
        int score = RiskScoreCalculator.computeOverallScore(List.of(f1, f2, f3));
        assertThat(score).isEqualTo(53);
        assertThat(RiskScoreCalculator.scoreToGrade(score)).isEqualTo("D");

        // Grade bands: A 0-10, B 11-30, C 31-50, D 51-75, F 76-100
        assertThat(RiskScoreCalculator.scoreToGrade(0)).isEqualTo("A");
        assertThat(RiskScoreCalculator.scoreToGrade(10)).isEqualTo("A");
        assertThat(RiskScoreCalculator.scoreToGrade(11)).isEqualTo("B");
        assertThat(RiskScoreCalculator.scoreToGrade(30)).isEqualTo("B");
        assertThat(RiskScoreCalculator.scoreToGrade(31)).isEqualTo("C");
        assertThat(RiskScoreCalculator.scoreToGrade(50)).isEqualTo("C");
        assertThat(RiskScoreCalculator.scoreToGrade(51)).isEqualTo("D");
        assertThat(RiskScoreCalculator.scoreToGrade(75)).isEqualTo("D");
        assertThat(RiskScoreCalculator.scoreToGrade(76)).isEqualTo("F");
        assertThat(RiskScoreCalculator.scoreToGrade(100)).isEqualTo("F");
    }

    @Test
    @DisplayName("Verify final reported scores ordering: self (with tests) > vulnerable-app > self (all) > self (production) = migrated-app = 0")
    void testRiskScoreOrdering() {
        // self (with tests): 14 CRITICAL, 14 HIGH -> 490 pts -> score 100
        List<ScanFinding> selfWithTests = new java.util.ArrayList<>();
        for (int i = 0; i < 14; i++) selfWithTests.add(createFinding(95, "CIPHER_BROKEN", false));
        for (int i = 0; i < 14; i++) selfWithTests.add(createFinding(85, "KEY_EXCHANGE_QV", true));

        // vulnerable-app: 9 CRITICAL, 5 HIGH -> 275 pts -> score 99
        List<ScanFinding> vulnerableApp = new java.util.ArrayList<>();
        for (int i = 0; i < 9; i++) vulnerableApp.add(createFinding(95, "CIPHER_BROKEN", false));
        for (int i = 0; i < 5; i++) vulnerableApp.add(createFinding(85, "KEY_EXCHANGE_QV", true));

        // self (all): 3 CRITICAL, 4 HIGH -> 115 pts -> score 85
        List<ScanFinding> selfAll = new java.util.ArrayList<>();
        for (int i = 0; i < 3; i++) selfAll.add(createFinding(95, "CIPHER_BROKEN", false));
        for (int i = 0; i < 4; i++) selfAll.add(createFinding(85, "KEY_EXCHANGE_QV", true));

        // self (production): 0 actionable findings -> 0 pts -> score 0
        List<ScanFinding> selfProduction = List.of(
                createFinding(0, "PQC_READY", false)
        );

        // migrated-app: 0 actionable findings -> 0 pts -> score 0
        List<ScanFinding> migratedApp = List.of(
                createFinding(0, "PQC_READY", false)
        );

        int selfTestsPoints = RiskScoreCalculator.computeRiskPoints(selfWithTests);
        int vulnPoints = RiskScoreCalculator.computeRiskPoints(vulnerableApp);
        int selfAllPoints = RiskScoreCalculator.computeRiskPoints(selfAll);
        int selfProdPoints = RiskScoreCalculator.computeRiskPoints(selfProduction);
        int migratedPoints = RiskScoreCalculator.computeRiskPoints(migratedApp);

        assertThat(selfTestsPoints).isEqualTo(490);
        assertThat(vulnPoints).isEqualTo(275);
        assertThat(selfAllPoints).isEqualTo(115);
        assertThat(selfProdPoints).isEqualTo(0);
        assertThat(migratedPoints).isEqualTo(0);

        int selfTestsScore = RiskScoreCalculator.computeOverallScore(selfWithTests);
        int vulnScore = RiskScoreCalculator.computeOverallScore(vulnerableApp);
        int selfAllScore = RiskScoreCalculator.computeOverallScore(selfAll);
        int selfProdScore = RiskScoreCalculator.computeOverallScore(selfProduction);
        int migratedScore = RiskScoreCalculator.computeOverallScore(migratedApp);

        // Actual values checked: self (with tests) (100) > vulnerable-app (99) > self (all) (85) > self (production) (0) == migrated-app (0)
        assertThat(selfTestsScore).isEqualTo(100);
        assertThat(vulnScore).isEqualTo(99);
        assertThat(selfAllScore).isEqualTo(85);
        assertThat(selfProdScore).isEqualTo(0);
        assertThat(migratedScore).isEqualTo(0);

        assertThat(selfTestsScore).isGreaterThan(vulnScore);
        assertThat(vulnScore).isGreaterThan(selfAllScore);
        assertThat(selfAllScore).isGreaterThan(selfProdScore);
        assertThat(selfProdScore).isEqualTo(migratedScore);
        assertThat(migratedScore).isEqualTo(0);

        assertThat(RiskScoreCalculator.scoreToGrade(selfTestsScore)).isEqualTo("F");
        assertThat(RiskScoreCalculator.scoreToGrade(vulnScore)).isEqualTo("F");
        assertThat(RiskScoreCalculator.scoreToGrade(selfAllScore)).isEqualTo("F");
        assertThat(RiskScoreCalculator.scoreToGrade(selfProdScore)).isEqualTo("A");
        assertThat(RiskScoreCalculator.scoreToGrade(migratedScore)).isEqualTo("A");
    }

    @Test
    @DisplayName("Verify repository with only INFO findings scores 0 / A")
    void testRepoWithOnlyInfoFindingsScoresZeroAndGradeA() {
        List<ScanFinding> infoFindings = List.of(
                createFinding(0, "PQC_READY", false),
                createFinding(20, "SYMMETRIC_INFO", false)
        );

        int score = RiskScoreCalculator.computeOverallScore(infoFindings);
        assertThat(score).isEqualTo(0);
        assertThat(RiskScoreCalculator.scoreToGrade(score)).isEqualTo("A");
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
