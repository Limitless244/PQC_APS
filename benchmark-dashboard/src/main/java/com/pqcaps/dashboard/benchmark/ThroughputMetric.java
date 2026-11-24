package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ThroughputMetric(
        @JsonProperty("recordSize") String recordSize,
        @JsonProperty("operation") String operation,
        @JsonProperty("throughputMBps") double throughputMBps,
        @JsonProperty("stdDevMBps") double stdDevMBps,
        @JsonProperty("forks") int forks,
        @JsonProperty("iterations") int iterations
) {
    public ThroughputMetric(String recordSize, String operation, double throughputMBps) {
        this(recordSize, operation, throughputMBps, 0.0, 1, 1);
    }
}
