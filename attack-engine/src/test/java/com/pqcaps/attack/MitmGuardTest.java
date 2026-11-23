package com.pqcaps.attack;

import com.pqcaps.auth.MlDsaSignatureScheme;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MitmGuardTest {

    private EventLog eventLog;
    private MitmGuard guard;
    private MlDsaSignatureScheme scheme;

    @BeforeEach
    void setUp() {
        eventLog = EventLog.getInstance();
        eventLog.clear();
        guard = new MitmGuard(eventLog);
        scheme = new MlDsaSignatureScheme();
    }

    @Test
    void failClosedWhenNoPinnedKeyProvided() {
        assertThatThrownBy(() -> guard.validateKeyPinningConfigured(null, false, "HYBRID"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("FAIL-CLOSED");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.MITM);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    void allowInsecureNoPinningLogsWarning() {
        guard.validateKeyPinningConfigured(null, true, "HYBRID");
        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.MITM);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.LOGGED);
    }

    @Test
    void signatureMismatchTriggersMitmEvent() {
        KeyPair legitimateKp = scheme.generateKeyPair();
        KeyPair attackerKp = scheme.generateKeyPair();

        byte[] transcript = "Handshake transcript data".getBytes();
        byte[] attackerSig = scheme.sign(attackerKp.getPrivate(), transcript);

        // Verification against legitimate pinned key must fail and emit MITM event
        assertThatThrownBy(() -> guard.verifyServerSignature(scheme, legitimateKp.getPublic(), transcript, attackerSig, "HYBRID"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("MITM attack detected");

        List<DetectionEvent> events = eventLog.getEventsByType(DetectionEvent.AttackType.MITM);
        assertThat(events).hasSize(1);
        assertThat(events.get(0).action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }
}
