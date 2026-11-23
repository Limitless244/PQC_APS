package com.pqcaps.scanner;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * An individual finding produced by the crypto scanner.
 */
public record ScanFinding(
        @JsonProperty("id") String id,
        @JsonProperty("ruleId") String ruleId,
        @JsonProperty("category") String category,
        @JsonProperty("file") String file,
        @JsonProperty("line") int line,
        @JsonProperty("redactedSnippet") String redactedSnippet,
        @JsonProperty("algorithm") String algorithm,
        @JsonProperty("quantumVulnerable") boolean quantumVulnerable,
        @JsonProperty("severity") String severity,
        @JsonProperty("riskScore") int riskScore,
        @JsonProperty("explanation") String explanation,
        @JsonProperty("recommendation") String recommendation,
        @JsonProperty("migrationTarget") String migrationTarget
) {}
