package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record BenchmarkSummary(
        @JsonProperty("handshakeWireOverheadRatio") double handshakeWireOverheadRatio,
        @JsonProperty("keyMaterialOverheadRatio") double keyMaterialOverheadRatio,
        @JsonProperty("hybridWireOverheadRatio") double hybridWireOverheadRatio,
        @JsonProperty("hybridCpuOverheadRatio") double hybridCpuOverheadRatio,
        @JsonProperty("classicalHandshakeWireBytes") int classicalHandshakeWireBytes,
        @JsonProperty("hybridHandshakeWireBytes") int hybridHandshakeWireBytes,
        @JsonProperty("analysis") String analysis
) {
    public BenchmarkSummary(double handshakeWireOverheadRatio, double keyMaterialOverheadRatio, double hybridCpuOverheadRatio, String analysis) {
        this(handshakeWireOverheadRatio, keyMaterialOverheadRatio, keyMaterialOverheadRatio, hybridCpuOverheadRatio, 820, 6433, analysis);
    }

    public BenchmarkSummary(double hybridWireOverheadRatio, double hybridCpuOverheadRatio, String analysis) {
        this(7.85, hybridWireOverheadRatio, hybridWireOverheadRatio, hybridCpuOverheadRatio, 820, 6433, analysis);
    }
}
