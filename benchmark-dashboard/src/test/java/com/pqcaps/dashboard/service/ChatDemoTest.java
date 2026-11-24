package com.pqcaps.dashboard.service;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attack.EventLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Chat Demo Service Verification")
class ChatDemoTest {

    private ChatDemoService chatService;

    @BeforeEach
    void setUp() {
        chatService = new ChatDemoService();
    }

    @Test
    @DisplayName("In HYBRID mode, messages encrypt, advance sequence number, and attacker sees only ciphertext")
    void hybridNormalFlow() {
        chatService.initSession("HYBRID");
        ChatDemoService.ChatSendResult res = chatService.sendMessage("Alice wire transfer $1000");

        assertThat(res.sender()).isEqualTo("Alice");
        assertThat(res.message()).isEqualTo("Alice wire transfer $1000");
        assertThat(res.sequenceNumber()).isEqualTo(0);
        assertThat(res.ciphertextHexTruncated()).isNotEmpty();
        assertThat(res.attackerView()).contains("[Encrypted Record seq=0]");
        assertThat(res.attackerView()).doesNotContain("wire transfer");
        assertThat(res.bobOutcome()).contains("ACCEPTED");
    }

    @Test
    @DisplayName("In HYBRID mode, replayed message is rejected by Bob and REPLAY event is logged")
    void hybridReplayRejectedAndLogged() {
        chatService.initSession("HYBRID");
        chatService.sendMessage("Payment authorized #1");

        int initialEventCount = EventLog.getInstance().getEvents().size();
        ChatDemoService.AttackerActionResult replayRes = chatService.replayLastMessage();

        assertThat(replayRes.action()).isEqualTo("REPLAY");
        assertThat(replayRes.outcome()).isEqualTo("BLOCKED");
        assertThat(replayRes.detail()).containsIgnoringCase("blocked by sequence validation");

        List<DetectionEvent> events = EventLog.getInstance().getEvents();
        assertThat(events.size()).isGreaterThan(initialEventCount);
        DetectionEvent lastEvent = EventLog.getInstance().getLastEvent();
        assertThat(lastEvent.attackType()).isEqualTo(DetectionEvent.AttackType.REPLAY);
        assertThat(lastEvent.action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    @DisplayName("In HYBRID mode, bit-flipped ciphertext is rejected by Bob and TAMPER event is logged")
    void hybridBitFlipRejectedAndLogged() {
        chatService.initSession("HYBRID");
        chatService.sendMessage("Confidential data payload");

        int initialEventCount = EventLog.getInstance().getEvents().size();
        ChatDemoService.AttackerActionResult tamperRes = chatService.flipBit();

        assertThat(tamperRes.action()).isEqualTo("TAMPER");
        assertThat(tamperRes.outcome()).isEqualTo("BLOCKED");
        assertThat(tamperRes.detail()).containsIgnoringCase("authentication tag mismatch");

        List<DetectionEvent> events = EventLog.getInstance().getEvents();
        assertThat(events.size()).isGreaterThan(initialEventCount);
        DetectionEvent lastEvent = EventLog.getInstance().getLastEvent();
        assertThat(lastEvent.attackType()).isEqualTo(DetectionEvent.AttackType.TAMPER);
        assertThat(lastEvent.action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    @DisplayName("In CLASSICAL-VULNERABLE mode, attacker observes plaintext and replay succeeds")
    void classicalVulnerableAllowsMitmAndReplay() {
        chatService.initSession("CLASSICAL-VULNERABLE");
        ChatDemoService.ChatSendResult res = chatService.sendMessage("Secret classical password");

        // MITM decrypts and sees plaintext
        assertThat(res.attackerView()).contains("[MITM Intercepted Plaintext]: \"Secret classical password\"");

        // Replay succeeds because sequence checks are disabled
        ChatDemoService.AttackerActionResult replayRes = chatService.replayLastMessage();
        assertThat(replayRes.action()).isEqualTo("REPLAY");
        assertThat(replayRes.outcome()).isEqualTo("SUCCEEDED");
    }

    @Test
    @DisplayName("In CLASSICAL-VULNERABLE mode with active MITM, attacker panel shows readable plaintext")
    void classicalVulnerableMitmShowsReadablePlaintext() {
        chatService.initSession("CLASSICAL-VULNERABLE");
        String secretMessage = "DynamicTransfer-" + java.util.UUID.randomUUID();
        ChatDemoService.ChatSendResult res = chatService.sendMessage(secretMessage);

        assertThat(res.attackerView()).contains("[MITM Intercepted Plaintext]: \"" + secretMessage + "\"");
        assertThat(res.attackerView()).contains(secretMessage);
        assertThat(res.attackerPlaintext()).isEqualTo(secretMessage);
    }

    @Test
    @DisplayName("In CLASSICAL-VULNERABLE mode, sends two different random messages and asserts attacker view equals each")
    void classicalVulnerableMitmDecryptsDynamicRandomMessages() {
        chatService.initSession("CLASSICAL-VULNERABLE");

        // Two distinct random messages (no fixed strings)
        String msg1 = "RandomMsg-1-" + java.util.UUID.randomUUID();
        String msg2 = "RandomMsg-2-" + java.util.UUID.randomUUID();

        assertThat(msg1).isNotEqualTo(msg2);

        // Send first random message
        ChatDemoService.ChatSendResult res1 = chatService.sendMessage(msg1);
        assertThat(res1.attackerView()).isEqualTo("[MITM Intercepted Plaintext]: \"" + msg1 + "\"");
        assertThat(res1.attackerPlaintext()).isEqualTo(msg1);

        // Send second random message
        ChatDemoService.ChatSendResult res2 = chatService.sendMessage(msg2);
        assertThat(res2.attackerView()).isEqualTo("[MITM Intercepted Plaintext]: \"" + msg2 + "\"");
        assertThat(res2.attackerPlaintext()).isEqualTo(msg2);
    }

    @Test
    @DisplayName("Invalid mode throws IllegalArgumentException")
    void invalidModeThrowsException() {
        assertThatThrownBy(() -> chatService.initSession("QUANTUM_BROKEN"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid chat mode");
    }

    @Test
    @DisplayName("Empty message throws IllegalArgumentException")
    void emptyMessageThrowsException() {
        chatService.initSession("HYBRID");
        assertThatThrownBy(() -> chatService.sendMessage(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be empty");
    }
}
