package com.pqcaps.attack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TamperGuardTest {

    private EventLog eventLog;
    private TamperGuard guard;

    @BeforeEach
    void setUp() {
        eventLog = EventLog.getInstance();
        eventLog.clear();
        guard = new TamperGuard(eventLog);
    }

    @Test
    void aeadTagTamperingReturnsGenericErrorAndLogsDetails() {
        AEADBadTagException badTag = new AEADBadTagException("Tag mismatch!");
        byte[] nonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

        SecurityException ex = guard.handleAeadTampering(badTag, 42, nonce, "HYBRID");

        // External error message is generic (no oracle for attackers)
        assertThat(ex.getMessage()).isEqualTo("Record decryption failed");

        // Forensic details are recorded in EventLog
        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.TAMPER);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).detail()).contains("seq=42");
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    void finishedTamperingReturnsGenericErrorAndLogsDetails() {
        SecurityException ex = guard.handleFinishedTampering("HYBRID", "Server verifyData mismatch");

        assertThat(ex.getMessage()).isEqualTo("Handshake failed");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.TAMPER);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).detail()).contains("Server verifyData mismatch");
    }
}
