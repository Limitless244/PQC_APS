package com.pqcaps.dashboard.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attacklab.SecurityMatrixResult;
import com.pqcaps.attacklab.SecurityMatrixRunner;
import com.pqcaps.common.DataPaths;
import com.pqcaps.common.SecurityEventSink;
import com.pqcaps.dashboard.benchmark.BenchmarkReport;
import com.pqcaps.dashboard.benchmark.BenchmarkRunner;
import com.pqcaps.scanner.ScanReport;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class DashboardDataService {

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    private final List<SseEmitter> sseEmitters = new CopyOnWriteArrayList<>();

    @PostConstruct
    public void init() {
        // Broadcast any event emitted through the global sink directly to connected SSE clients
        SecurityEventSink.register((type, sev, comp, suite, act, detail) -> {
            try {
                DetectionEvent.AttackType at = DetectionEvent.AttackType.valueOf(type.toUpperCase());
                DetectionEvent.Severity sv = DetectionEvent.Severity.valueOf(sev.toUpperCase());
                DetectionEvent.Action ac = DetectionEvent.Action.valueOf(act.toUpperCase());
                DetectionEvent event = DetectionEvent.create(at, sv, comp, suite, ac, detail);
                broadcastEvent(event);
            } catch (Exception ignored) {}
        });
    }

    public List<SecurityMatrixResult> loadAttacks() {
        Path path = resolveFile("attack-results.json");
        if (!Files.exists(path)) {
            throw new NoSuchElementException("Attack matrix results file not found: " + path.getFileName());
        }
        try {
            return SecurityMatrixResult.loadFromJson(path.toFile());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse attack matrix results from " + path.getFileName() + ": " + e.getMessage());
        }
    }

    public List<DetectionEvent> loadEvents(int limit) {
        Path path = resolveFile("detection-events.jsonl");
        if (!Files.exists(path)) {
            return Collections.emptyList();
        }
        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            List<DetectionEvent> events = new ArrayList<>();
            for (String line : lines) {
                if (line == null || line.isBlank()) continue;
                try {
                    events.add(mapper.readValue(line, DetectionEvent.class));
                } catch (Exception ignored) {}
            }
            // Reverse so newest events appear first
            Collections.reverse(events);
            if (limit > 0 && events.size() > limit) {
                return events.subList(0, limit);
            }
            return events;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read events from " + path.getFileName() + ": " + e.getMessage());
        }
    }

    public ScanReport loadScanReport(String target) {
        if (!List.of("vulnerable", "migrated", "self").contains(target.toLowerCase())) {
            throw new IllegalArgumentException("Invalid scan target '" + target + "'. Allowed targets: vulnerable, migrated, self");
        }
        String filename = "scan-report-" + target.toLowerCase() + ".json";
        Path path = resolveFile(filename);
        if (!Files.exists(path)) {
            throw new NoSuchElementException("Scan report not found for target: " + target);
        }
        try {
            return ScanReport.loadFromJson(path.toFile());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse scan report for " + target + ": " + e.getMessage());
        }
    }

    public BenchmarkReport loadBenchmarks() {
        Path path = resolveFile("benchmark-results.json");
        if (!Files.exists(path)) {
            // Lazily generate a benchmark report if missing
            return BenchmarkRunner.run(true);
        }
        try {
            return BenchmarkReport.loadFromJson(path.toFile());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse benchmark results from " + path.getFileName() + ": " + e.getMessage());
        }
    }

    public synchronized List<SecurityMatrixResult> runAttacks() {
        SecurityMatrixRunner runner = new SecurityMatrixRunner();
        List<SecurityMatrixResult> matrix = runner.runFullMatrix();

        Path out = DataPaths.resolve("attack-results.json");
        try {
            SecurityMatrixResult.saveToJson(out.toFile(), matrix);
        } catch (IOException e) {
            System.err.println("[Dashboard] Failed to save updated attack-results.json: " + e.getMessage());
        }

        // Notify SSE clients of the update
        broadcastEvent(DetectionEvent.create(
                DetectionEvent.AttackType.DOWNGRADE,
                DetectionEvent.Severity.LOW,
                "SecurityMatrixRunner",
                "ALL",
                DetectionEvent.Action.LOGGED,
                "Security matrix run completed with " + matrix.size() + " test cells evaluated."
        ));

        return matrix;
    }

    public SseEmitter registerEmitter() {
        SseEmitter emitter = new SseEmitter(180_000L); // 3 minutes timeout
        sseEmitters.add(emitter);

        emitter.onCompletion(() -> sseEmitters.remove(emitter));
        emitter.onTimeout(() -> sseEmitters.remove(emitter));
        emitter.onError(e -> sseEmitters.remove(emitter));

        // Send initial connection event
        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data("Connected to PQC-APS Live Event Feed"));
        } catch (Exception e) {
            sseEmitters.remove(emitter);
        }

        return emitter;
    }

    public void broadcastEvent(DetectionEvent event) {
        if (event == null) return;
        List<SseEmitter> dead = new ArrayList<>();
        for (SseEmitter emitter : sseEmitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name("event")
                        .data(event));
            } catch (Exception e) {
                dead.add(emitter);
            }
        }
        sseEmitters.removeAll(dead);
    }

    public Path resolveFile(String filename) {
        Path primary = DataPaths.resolve(filename);
        if (Files.exists(primary)) {
            return primary;
        }
        // Fallback to sample directory
        Path sample = DataPaths.resolve("sample/" + filename);
        if (Files.exists(sample)) {
            return sample;
        }
        Path rootSample = Path.of("data", "sample", filename);
        if (Files.exists(rootSample)) {
            return rootSample;
        }
        return primary;
    }
}
