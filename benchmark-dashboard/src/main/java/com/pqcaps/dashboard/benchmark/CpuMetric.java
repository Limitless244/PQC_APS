package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CpuMetric(
        @JsonProperty("suite") String suite,
        @JsonProperty("avgCpuMicroseconds") double avgCpuMicroseconds,
        @JsonProperty("limitation") String limitation
) {}
