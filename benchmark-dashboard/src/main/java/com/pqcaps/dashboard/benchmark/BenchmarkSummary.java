package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record BenchmarkSummary(
        @JsonProperty("hybridWireOverheadRatio") double hybridWireOverheadRatio,
        @JsonProperty("hybridCpuOverheadRatio") double hybridCpuOverheadRatio,
        @JsonProperty("analysis") String analysis
) {}
