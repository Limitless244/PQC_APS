package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SizeMetric(
        @JsonProperty("category") String category,
        @JsonProperty("item") String item,
        @JsonProperty("suite") String suite,
        @JsonProperty("rawBytes") int rawBytes,
        @JsonProperty("encodedBytes") int encodedBytes,
        @JsonProperty("note") String note
) {}
