package com.pqcaps.scanner;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Top-level report serialized to {@code scan-report.json}.
 */
public record ScanReport(
        @JsonProperty("scanId") String scanId,
        @JsonProperty("target") String target,
        @JsonProperty("timestamp") String timestamp,
        @JsonProperty("summary") ScanSummary summary,
        @JsonProperty("findings") List<ScanFinding> findings
) {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static void saveToJson(File file, ScanReport report) throws IOException {
        MAPPER.writeValue(file, report);
    }

    public static ScanReport loadFromJson(File file) throws IOException {
        return MAPPER.readValue(file, ScanReport.class);
    }
}
