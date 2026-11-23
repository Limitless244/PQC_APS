package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MachineInfo(
        @JsonProperty("jdkVersion") String jdkVersion,
        @JsonProperty("jdkVendor") String jdkVendor,
        @JsonProperty("jvmName") String jvmName,
        @JsonProperty("osName") String osName,
        @JsonProperty("osArch") String osArch,
        @JsonProperty("cpuCores") int cpuCores,
        @JsonProperty("timestamp") String timestamp
) {}
