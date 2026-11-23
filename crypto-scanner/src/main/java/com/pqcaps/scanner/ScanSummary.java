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
        @JsonProperty("grade") String grade,
        @JsonProperty("quantumReadiness") double quantumReadiness
) {}
