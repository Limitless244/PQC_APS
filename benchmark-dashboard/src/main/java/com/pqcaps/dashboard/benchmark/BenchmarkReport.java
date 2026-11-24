package com.pqcaps.dashboard.benchmark;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.util.List;

public record BenchmarkReport(
        @JsonProperty("mode") String mode,
        @JsonProperty("machine") MachineInfo machine,
        @JsonProperty("sizes") List<SizeMetric> sizes,
        @JsonProperty("latency") List<LatencyMetric> latency,
        @JsonProperty("cpu") List<CpuMetric> cpu,
        @JsonProperty("throughput") List<ThroughputMetric> throughput,
        @JsonProperty("summary") BenchmarkSummary summary
) {
    public BenchmarkReport(MachineInfo machine, List<SizeMetric> sizes, List<LatencyMetric> latency, List<CpuMetric> cpu, List<ThroughputMetric> throughput, BenchmarkSummary summary) {
        this("QUICK", machine, sizes, latency, cpu, throughput, summary);
    }

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static void saveToJson(File file, BenchmarkReport report) throws IOException {
        MAPPER.writeValue(file, report);
    }

    public static BenchmarkReport loadFromJson(File file) throws IOException {
        return MAPPER.readValue(file, BenchmarkReport.class);
    }
}
