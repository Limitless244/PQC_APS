package com.pqcaps.scanner;

import java.util.*;

/**
 * Risk scoring calculator based on NIST guidelines, Harvest-Now-Decrypt-Later threats,
 * and data lifetime considerations.
 *
 * <p><b>Base Scores by Category:</b>
 * <ul>
 *   <li>{@code CIPHER_BROKEN} / {@code CIPHER_WEAK}: 95</li>
 *   <li>{@code SECRET_HARDCODED}: 90</li>
 *   <li>{@code RNG_WEAK}: 80</li>
 *   <li>{@code KEY_EXCHANGE_QV} / {@code ENCRYPTION_QV}: 85</li>
 *   <li>{@code TLS_LEGACY}: 80</li>
 *   <li>{@code HASH_BROKEN}: 70</li>
 *   <li>{@code SIGNATURE_QV}: 60</li>
 *   <li>{@code SYMMETRIC_INFO} (AES-128): 20</li>
 *   <li>{@code PQC_READY}: 0</li>
 * </ul>
 *
 * <p><b>Data Lifetime Multiplier:</b>
 * If {@code dataLifetimeYears > 10}, key exchange and encryption findings are multiplied by 1.2
 * (capped at 100), reflecting increased risk of retroactive quantum decryption.
 *
 * <p><b>Overall Score Formula:</b>
 * {@code overallScore = 0.6 * max(findings) + 0.4 * average(findings)}
 */
public final class RiskScoreCalculator {

    public static final int DEFAULT_DATA_LIFETIME_YEARS = 10;

    private RiskScoreCalculator() {}

    /**
     * Computes the risk score (0 to 100) for an individual finding given its category and data lifetime.
     */
    public static int computeRiskScore(String category, int baseScore, int dataLifetimeYears) {
        if ("PQC_READY".equalsIgnoreCase(category)) {
            return 0;
        }

        int score = baseScore;
        // Fallback default base if not provided in rule
        if (score <= 0) {
            score = switch (category.toUpperCase()) {
                case "CIPHER_BROKEN", "CIPHER_WEAK" -> 95;
                case "SECRET_HARDCODED" -> 90;
                case "KEY_EXCHANGE_QV", "ENCRYPTION_QV" -> 85;
                case "RNG_WEAK", "TLS_LEGACY" -> 80;
                case "HASH_BROKEN" -> 70;
                case "SIGNATURE_QV" -> 60;
                case "SYMMETRIC_INFO" -> 20;
                default -> 40;
            };
        }

        // Apply dataLifetimeYears multiplier to key exchange and encryption
        if (dataLifetimeYears > 10 &&
                ("KEY_EXCHANGE_QV".equalsIgnoreCase(category) || "ENCRYPTION_QV".equalsIgnoreCase(category))) {
            score = (int) Math.round(score * 1.2);
        }

        return Math.min(100, Math.max(0, score));
    }

    /**
     * Determines the severity string from the calculated risk score.
     */
    public static String scoreToSeverity(int score, String category) {
        if ("PQC_READY".equalsIgnoreCase(category) || "SYMMETRIC_INFO".equalsIgnoreCase(category)) {
            return "INFO";
        }
        if (score >= 90) return "CRITICAL";
        if (score >= 70) return "HIGH";
        if (score >= 40) return "MEDIUM";
        if (score >= 10) return "LOW";
        return "INFO";
    }

    /**
     * Computes the raw risk points:
     * {@code points = 25*CRITICAL + 10*HIGH + 3*MEDIUM + 1*LOW}, with {@code INFO = 0}.
     */
    public static int computeRiskPoints(List<ScanFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return 0;
        }

        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;

        for (ScanFinding f : findings) {
            String sev = f.severity() != null ? f.severity().toUpperCase() : "";
            switch (sev) {
                case "CRITICAL" -> critical++;
                case "HIGH" -> high++;
                case "MEDIUM" -> medium++;
                case "LOW" -> low++;
                default -> {} // INFO = 0
            }
        }

        return 25 * critical + 10 * high + 3 * medium + 1 * low;
    }

    /**
     * Converts raw risk points into the non-linear reported risk score (0 to 100):
     * {@code score = round(100 * (1 - exp(-points / 60.0)))}.
     * This ensures monotonic growth with severity and count without premature hard capping.
     */
    public static int pointsToScore(int points) {
        if (points <= 0) {
            return 0;
        }
        double normalized = 100.0 * (1.0 - Math.exp(-points / 60.0));
        return (int) Math.round(normalized);
    }

    /**
     * Computes the project-level overall risk score:
     * {@code score = round(100 * (1 - exp(-points / 60.0)))} where
     * {@code points = 25*CRITICAL + 10*HIGH + 3*MEDIUM + 1*LOW}.
     */
    public static int computeOverallScore(List<ScanFinding> findings) {
        int points = computeRiskPoints(findings);
        return pointsToScore(points);
    }

    /**
     * Computes the Letter Grade from the overall score:
     * A: 0-10, B: 11-30, C: 31-50, D: 51-75, F: 76-100.
     */
    public static String scoreToGrade(int overallScore) {
        if (overallScore <= 10) return "A";
        if (overallScore <= 30) return "B";
        if (overallScore <= 50) return "C";
        if (overallScore <= 75) return "D";
        return "F";
    }

    /**
     * Computes the Quantum Readiness percentage:
     * {@code PQC-ready algorithm uses / (PQC-ready + quantum-vulnerable public-key algorithm uses) * 100.0}
     */
    public static double computeQuantumReadiness(List<ScanFinding> findings) {
        long pqcReadyCount = findings.stream()
                .filter(f -> "PQC_READY".equalsIgnoreCase(f.category()))
                .count();

        long qvCount = findings.stream()
                .filter(ScanFinding::quantumVulnerable)
                .count();

        long totalPublicKeyUses = pqcReadyCount + qvCount;
        if (totalPublicKeyUses == 0) {
            return 100.0; // No public-key crypto or no quantum vulnerabilities
        }

        double readiness = ((double) pqcReadyCount / (double) totalPublicKeyUses) * 100.0;
        return Math.round(readiness * 10.0) / 10.0;
    }

    /**
     * Builds the complete ScanSummary for a list of findings.
     */
    public static ScanSummary createSummary(List<ScanFinding> findings) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("CRITICAL", 0);
        counts.put("HIGH", 0);
        counts.put("MEDIUM", 0);
        counts.put("LOW", 0);
        counts.put("INFO", 0);

        for (ScanFinding f : findings) {
            String sev = f.severity().toUpperCase();
            counts.put(sev, counts.getOrDefault(sev, 0) + 1);
        }

        int riskPoints = computeRiskPoints(findings);
        int overallScore = pointsToScore(riskPoints);
        String grade = scoreToGrade(overallScore);
        double quantumReadiness = computeQuantumReadiness(findings);

        return new ScanSummary(findings.size(), counts, overallScore, riskPoints, grade, quantumReadiness);
    }
}
