package com.pqcaps.attack;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class EventLogTest {

    private EventLog eventLog;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        eventLog = EventLog.getInstance();
        eventLog.clear();
        eventLog.setLogFilePath(tempDir.resolve("test-events.jsonl"));
    }

    @AfterEach
    void tearDown() {
        eventLog.clear();
        eventLog.setLogFilePath(Path.of("detection-events.jsonl"));
    }

    @Test
    void eventLoggingAndJsonlPersistence() throws Exception {
        DetectionEvent event = eventLog.record(
                DetectionEvent.AttackType.DOWNGRADE,
                DetectionEvent.Severity.HIGH,
                "TestComponent",
                "HYBRID",
                DetectionEvent.Action.BLOCKED,
                "Attempted removal of HYBRID suite"
        );

        assertThat(eventLog.getEvents()).hasSize(1);
        assertThat(eventLog.getLastEvent().id()).isEqualTo(event.id());
        assertThat(eventLog.getEventsByType(DetectionEvent.AttackType.DOWNGRADE)).hasSize(1);

        // Verify jsonl file output
        assertThat(Files.exists(eventLog.getLogFilePath())).isTrue();
        List<String> lines = Files.readAllLines(eventLog.getLogFilePath());
        assertThat(lines).hasSize(1);
        assertThat(lines.get(0)).contains("\"attackType\":\"DOWNGRADE\"");
        assertThat(lines.get(0)).contains("\"action\":\"BLOCKED\"");
    }
}
