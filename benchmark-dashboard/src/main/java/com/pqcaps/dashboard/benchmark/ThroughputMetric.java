package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ThroughputMetric(
        @JsonProperty("recordSize") String recordSize,
        @JsonProperty("operation") String operation,
        @JsonProperty("throughputMBps") double throughputMBps
) {}
