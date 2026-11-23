package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record LatencyMetric(
        @JsonProperty("operation") String operation,
        @JsonProperty("suiteOrAlgorithm") String suiteOrAlgorithm,
        @JsonProperty("avgMicroseconds") double avgMicroseconds,
        @JsonProperty("p95Microseconds") double p95Microseconds
) {}
