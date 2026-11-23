package com.pqcaps.attacklab;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Record representing the outcome and forensic evidence of an attack execution.
 *
 * <p>Phase 2 produces these results demonstrating vulnerability exploitation.
 * Phase 4 and the dashboard will read these records to verify that attack prevention
 * turns previously successful attacks into detected, blocked failures.
 *
 * @param name            human-readable attack name (e.g. "Downgrade Attack")
 * @param success         {@code true} if the attack achieved its malicious goal against the baseline
 * @param evidence        concrete diagnostic log / cryptographic proof (truncated hex, recovered text)
 * @param vulnerabilityId the vulnerability identifier exploited (e.g. "VULN-1")
 */
public record AttackResult(
        @JsonProperty("name") String name,
        @JsonProperty("success") boolean success,
        @JsonProperty("evidence") String evidence,
        @JsonProperty("vulnerabilityId") String vulnerabilityId
) {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * Saves a list of attack results to the specified JSON file.
     *
     * @param file    target file (e.g. {@code attack-results.json})
     * @param results list of results to persist
     * @throws IOException if writing fails
     */
    public static void saveToJson(File file, List<AttackResult> results) throws IOException {
        MAPPER.writeValue(file, results);
    }

    /**
     * Reads attack results from a JSON file.
     */
    public static List<AttackResult> loadFromJson(File file) throws IOException {
        return MAPPER.readValue(file, MAPPER.getTypeFactory().constructCollectionType(List.class, AttackResult.class));
    }
}
