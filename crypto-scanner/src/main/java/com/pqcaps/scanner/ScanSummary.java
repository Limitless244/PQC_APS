package com.pqcaps.scanner;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * Statistical summary of a cryptographic scan.
 */
public record ScanSummary(
        @JsonProperty("totalFindings") int totalFindings,
        @JsonProperty("countsBySeverity") Map<String, Integer> countsBySeverity,
        @JsonProperty("overallScore") int overallScore,
        @JsonProperty("riskPoints") int riskPoints,
        @JsonProperty("grade") String grade,
        @JsonProperty("quantumReadiness") double quantumReadiness
) {
    public ScanSummary(int totalFindings, Map<String, Integer> countsBySeverity, int overallScore, String grade, double quantumReadiness) {
        this(totalFindings, countsBySeverity, overallScore, overallScore, grade, quantumReadiness);
    }
}
