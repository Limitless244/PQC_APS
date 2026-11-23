package com.pqcaps.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.pqcaps.common.SecurityEventSink;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Thread-safe event repository and append-only {@code detection-events.jsonl} writer.
 *
 * <p>All guards in the Attack Engine record events here. The Phase 6 dashboard
 * reads from this persistent log to display real-time attack alerts.
 */
public final class EventLog {

    private static final EventLog INSTANCE = new EventLog();
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    static {
        // Register listener with common module's event sink
        SecurityEventSink.register((type, sev, comp, suite, act, detail) -> {
            try {
                DetectionEvent.AttackType at = DetectionEvent.AttackType.valueOf(type.toUpperCase());
                DetectionEvent.Severity sv = DetectionEvent.Severity.valueOf(sev.toUpperCase());
                DetectionEvent.Action ac = DetectionEvent.Action.valueOf(act.toUpperCase());
                INSTANCE.record(at, sv, comp, suite, ac, detail);
            } catch (Exception ignored) {}
        });
    }

    private final List<DetectionEvent> events = new CopyOnWriteArrayList<>();
    private Path logFilePath = Path.of("detection-events.jsonl");

    private EventLog() {}

    public static EventLog getInstance() {
        return INSTANCE;
    }

    /**
     * Configures the path of the append-only jsonl log file.
     */
    public synchronized void setLogFilePath(Path path) {
        this.logFilePath = path;
    }

    public Path getLogFilePath() {
        return logFilePath;
    }

    /**
     * Records a detection event in-memory and appends it to {@code detection-events.jsonl}.
     */
    public synchronized void log(DetectionEvent event) {
        if (event == null) return;
        events.add(event);

        try {
            if (logFilePath.getParent() != null) {
                Files.createDirectories(logFilePath.getParent());
            }
            String line = MAPPER.writeValueAsString(event) + System.lineSeparator();
            Files.writeString(
                    logFilePath,
                    line,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            System.err.println("[EventLog] Failed to append event to " + logFilePath + ": " + e.getMessage());
        }
    }

    /**
     * Helper to create and log an event in a single call.
     */
    public DetectionEvent record(
            DetectionEvent.AttackType attackType,
            DetectionEvent.Severity severity,
            String component,
            String suite,
            DetectionEvent.Action action,
            String detail) {
        DetectionEvent event = DetectionEvent.create(attackType, severity, component, suite, action, detail);
        log(event);
        return event;
    }

    /**
     * Returns an unmodifiable snapshot of all recorded events in memory.
     */
    public List<DetectionEvent> getEvents() {
        return Collections.unmodifiableList(new ArrayList<>(events));
    }

    /**
     * Filters events by attack type.
     */
    public List<DetectionEvent> getEventsByType(DetectionEvent.AttackType type) {
        return events.stream()
                .filter(e -> e.attackType() == type)
                .collect(Collectors.toList());
    }

    /**
     * Returns the most recent event, or {@code null} if empty.
     */
    public DetectionEvent getLastEvent() {
        return events.isEmpty() ? null : events.get(events.size() - 1);
    }

    /**
     * Clears all in-memory events and optionally removes the jsonl file.
     */
    public synchronized void clear() {
        events.clear();
        try {
            Files.deleteIfExists(logFilePath);
        } catch (IOException ignored) {}
    }
}
