package com.pqcaps.attack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DowngradeGuardTest {

    private EventLog eventLog;
    private DowngradeGuard guard;

    @BeforeEach
    void setUp() {
        eventLog = EventLog.getInstance();
        eventLog.clear();
        guard = new DowngradeGuard(eventLog);
    }

    @Test
    void rejectsClassicalWhenPolicyActive() {
        assertThatThrownBy(() -> guard.validateServerPolicy(
                List.of("CLASSICAL"), "CLASSICAL", true, "HYBRID"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Downgrade blocked");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.DOWNGRADE);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).severity()).isEqualTo(DetectionEvent.Severity.HIGH);
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    void allowsHybridWhenPolicyDemandsHybrid() {
        guard.validateServerPolicy(List.of("HYBRID"), "HYBRID", true, "HYBRID");
        assertThat(eventLog.getEvents()).isEmpty();
    }

    @Test
    void detectsTranscriptSuiteListMismatch() {
        assertThatThrownBy(() -> guard.validateTranscriptSuiteBinding(
                List.of("HYBRID", "CLASSICAL"), List.of("CLASSICAL"), "HYBRID"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Downgrade attack detected");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.DOWNGRADE);
        assertThat(events).hasSize(1);
    }
}
