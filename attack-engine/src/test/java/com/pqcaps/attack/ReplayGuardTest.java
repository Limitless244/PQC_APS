package com.pqcaps.attack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReplayGuardTest {

    private EventLog eventLog;
    private ReplayGuard guard;

    @BeforeEach
    void setUp() {
        eventLog = EventLog.getInstance();
        eventLog.clear();
        guard = new ReplayGuard(64, eventLog);
    }

    @Test
    void strictSequentialModeAcceptsIncreasingSequence() {
        guard.validateStrictSequence(0, "C2S", "HYBRID");
        guard.validateStrictSequence(1, "C2S", "HYBRID");
        guard.validateStrictSequence(2, "C2S", "HYBRID");

        assertThat(guard.getExpectedNextSeq()).isEqualTo(3);
        assertThat(eventLog.getEvents()).isEmpty();
    }

    @Test
    void strictSequentialModeRejectsOldSequence() {
        guard.validateStrictSequence(0, "C2S", "HYBRID");
        guard.validateStrictSequence(1, "C2S", "HYBRID");

        // Replay of sequence number 0
        assertThatThrownBy(() -> guard.validateStrictSequence(0, "C2S", "HYBRID"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Replay attack detected");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.REPLAY);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    void windowedModeRejectsDuplicates() {
        guard.validateWindowedSequence(0, "C2S", "HYBRID");
        guard.validateWindowedSequence(1, "C2S", "HYBRID");

        // Duplicate seq=1
        assertThatThrownBy(() -> guard.validateWindowedSequence(1, "C2S", "HYBRID"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("duplicate sequence number");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.REPLAY);
        assertThat(events).hasSize(1);
    }
}
