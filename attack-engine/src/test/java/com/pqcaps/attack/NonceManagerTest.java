package com.pqcaps.attack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NonceManagerTest {

    private EventLog eventLog;

    @BeforeEach
    void setUp() {
        eventLog = EventLog.getInstance();
        eventLog.clear();
    }

    @Test
    void generatesUniqueMonotonicNonces() {
        NonceManager manager = new NonceManager(100, eventLog);

        byte[] nonce1 = manager.nextNonce("HYBRID");
        byte[] nonce2 = manager.nextNonce("HYBRID");

        assertThat(nonce1).hasSize(12);
        assertThat(nonce2).hasSize(12);
        assertThat(nonce1).isNotEqualTo(nonce2);
        assertThat(manager.getCurrentCounter()).isEqualTo(2);
        assertThat(eventLog.getEvents()).isEmpty();
    }

    @Test
    void rejectsDuplicateReceivedNonce() {
        NonceManager manager = new NonceManager(100, eventLog);
        byte[] nonce = manager.nextNonce("HYBRID");

        // Recording the same nonce again must throw NonceReuseException
        assertThatThrownBy(() -> manager.recordReceivedNonce(nonce, "HYBRID"))
                .isInstanceOf(NonceReuseException.class)
                .hasMessageContaining("Inbound nonce reuse detected");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.NONCE_REUSE);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    void forcesRekeyAtMessageLimit() {
        // Small threshold: 3 messages max
        NonceManager manager = new NonceManager(3, eventLog);

        manager.nextNonce("HYBRID"); // seq 0
        manager.nextNonce("HYBRID"); // seq 1
        manager.nextNonce("HYBRID"); // seq 2

        assertThat(manager.isRekeyNeeded()).isTrue();

        // 4th message exceeds limit -> throws RekeyRequiredException
        assertThatThrownBy(() -> manager.nextNonce("HYBRID"))
                .isInstanceOf(RekeyRequiredException.class)
                .hasMessageContaining("rekey");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.NONCE_REUSE);
        assertThat(events).hasSize(1);
    }
}
