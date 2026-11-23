package com.pqcaps.scanner;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Representation of a cryptographic audit rule loaded from {@code rules.yaml}.
 */
public record Rule(
        @JsonProperty("id") String id,
        @JsonProperty("name") String name,
        @JsonProperty("category") String category,
        @JsonProperty("quantumVulnerable") boolean quantumVulnerable,
        @JsonProperty("severity") String severity,
        @JsonProperty("baseScore") int baseScore,
        @JsonProperty("explanation") String explanation,
        @JsonProperty("recommendation") String recommendation,
        @JsonProperty("migrationTarget") String migrationTarget
) {}
