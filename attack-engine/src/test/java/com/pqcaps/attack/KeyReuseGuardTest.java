package com.pqcaps.attack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyReuseGuardTest {

    private EventLog eventLog;
    private KeyReuseGuard guard;

    @BeforeEach
    void setUp() {
        eventLog = EventLog.getInstance();
        eventLog.clear();
        guard = new KeyReuseGuard(eventLog);
    }

    @Test
    void allowsUniqueEphemeralKeys() {
        byte[] key1 = new byte[]{1, 2, 3, 4};
        byte[] key2 = new byte[]{5, 6, 7, 8};

        guard.registerEphemeralKey(key1, "HYBRID");
        guard.registerEphemeralKey(key2, "HYBRID");

        assertThat(guard.isRegistered(key1)).isTrue();
        assertThat(guard.isRegistered(key2)).isTrue();
        assertThat(eventLog.getEvents()).isEmpty();
    }

    @Test
    void rejectsDuplicateEphemeralKey() {
        byte[] key = new byte[]{10, 20, 30, 40};

        guard.registerEphemeralKey(key, "HYBRID");

        // Attempting to register the same ephemeral key again must fail and log KEY_REUSE
        assertThatThrownBy(() -> guard.registerEphemeralKey(key, "HYBRID"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Ephemeral key reuse detected");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.KEY_REUSE);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).severity()).isEqualTo(DetectionEvent.Severity.HIGH);
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }
}
