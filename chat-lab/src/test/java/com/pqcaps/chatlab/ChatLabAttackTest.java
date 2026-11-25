package com.pqcaps.chatlab;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attack.EventLog;
import com.pqcaps.chatlab.model.AttackerActionOutcome;
import com.pqcaps.chatlab.model.CapturedTrafficRecord;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.chatlab.service.ChatLabAttackerService;
import com.pqcaps.chatlab.service.ChatLabClientService;
import com.pqcaps.chatlab.service.ChatLabServerService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ChatLabAttackTest {

    private ChatLabServerService serverService;
    private ChatLabAttackerService attackerService;
    private ChatLabClientService clientService;

    @AfterEach
    void tearDown() {
        if (clientService != null) clientService.disconnect();
        if (attackerService != null) attackerService.stop();
        if (serverService != null) serverService.stop();
    }

    // ── 1. REPLAY ATTACK TEST ──────────────────────────────────────────────

    @Test
    @DisplayName("Attack: Replay is ACCEPTED in CLASSICAL-VULNERABLE mode")
    void testReplay_AcceptedInClassicalVulnerable() throws Exception {
        setupSession(ChatMode.CLASSICAL_VULNERABLE);
        clientService.sendMessage("Payment order $100 (seq=0)");
        Thread.sleep(100);

        // Attacker replays last captured record
        AttackerActionOutcome outcome = attackerService.replayLastRecord();
        assertThat(outcome.status()).isEqualTo("FORWARDED");
        Thread.sleep(150);

        // In vulnerable mode, Bob accepts the replayed record without sequence validation!
        List<ChatMessageRecord> received = serverService.getReceivedMessages();
        assertThat(received).hasSize(2);
        assertThat(received.get(0).status()).isEqualTo("ACCEPTED");
        assertThat(received.get(1).status()).isEqualTo("ACCEPTED");
        assertThat(received.get(1).sequenceNumber()).isEqualTo(0); // Duplicate sequence number!
    }

    @Test
    @DisplayName("Attack: Replay is REJECTED by ReplayGuard in CLASSICAL-HARDENED mode")
    void testReplay_RejectedInClassicalHardened() throws Exception {
        setupSession(ChatMode.CLASSICAL_HARDENED);
        clientService.sendMessage("Payment order $100 (seq=0)");
        Thread.sleep(100);

        int initialEventCount = EventLog.getInstance().getEvents().size();

        // Attacker replays last record
        AttackerActionOutcome outcome = attackerService.replayLastRecord();
        assertThat(outcome.status()).isEqualTo("FORWARDED");
        Thread.sleep(150);

        // In hardened mode, ReplayGuard rejects duplicate sequence number
        List<ChatMessageRecord> received = serverService.getReceivedMessages();
        assertThat(received).hasSize(2);
        assertThat(received.get(0).status()).contains("ACCEPTED");
        assertThat(received.get(1).status()).contains("REJECTED");
        assertThat(received.get(1).guardFired()).isEqualTo("ReplayGuard");

        // Assert EventLog emitted REPLAY event
        assertThat(EventLog.getInstance().getEvents().size()).isGreaterThan(initialEventCount);
        DetectionEvent lastEvent = EventLog.getInstance().getLastEvent();
        assertThat(lastEvent.attackType()).isEqualTo(DetectionEvent.AttackType.REPLAY);
        assertThat(lastEvent.action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    @DisplayName("Attack: Replay is REJECTED by ReplayGuard in HYBRID mode")
    void testReplay_RejectedInHybrid() throws Exception {
        setupSession(ChatMode.HYBRID);
        clientService.sendMessage("PQ payment order $100 (seq=0)");
        Thread.sleep(100);

        int initialEventCount = EventLog.getInstance().getEvents().size();

        // Attacker replays last record
        attackerService.replayLastRecord();
        Thread.sleep(150);

        List<ChatMessageRecord> received = serverService.getReceivedMessages();
        assertThat(received).hasSize(2);
        assertThat(received.get(0).status()).contains("ACCEPTED");
        assertThat(received.get(1).status()).contains("REJECTED");
        assertThat(received.get(1).guardFired()).isEqualTo("ReplayGuard");

        DetectionEvent lastEvent = EventLog.getInstance().getLastEvent();
        assertThat(lastEvent.attackType()).isEqualTo(DetectionEvent.AttackType.REPLAY);
    }

    // ── 2. BIT-FLIP / TAMPERING TEST ───────────────────────────────────────

    @Test
    @DisplayName("Attack: Bit-flip is REJECTED with TAMPER event in CLASSICAL-HARDENED mode")
    void testBitFlip_RejectedWithTamperEvent_Hardened() throws Exception {
        setupSession(ChatMode.CLASSICAL_HARDENED);
        clientService.sendMessage("Legitimate transaction seq=0");
        Thread.sleep(100);

        int initialEventCount = EventLog.getInstance().getEvents().size();

        // Attacker flips bit in ciphertext
        AttackerActionOutcome outcome = attackerService.flipBit();
        assertThat(outcome.status()).isEqualTo("FORWARDED");
        Thread.sleep(150);

        List<ChatMessageRecord> received = serverService.getReceivedMessages();
        assertThat(received).hasSize(2);
        assertThat(received.get(1).status()).contains("REJECTED");
        assertThat(received.get(1).guardFired()).isEqualTo("TamperGuard");

        // Verify TAMPER event emitted
        assertThat(EventLog.getInstance().getEvents().size()).isGreaterThan(initialEventCount);
        DetectionEvent lastEvent = EventLog.getInstance().getLastEvent();
        assertThat(lastEvent.attackType()).isEqualTo(DetectionEvent.AttackType.TAMPER);
        assertThat(lastEvent.action()).isEqualTo(DetectionEvent.Action.BLOCKED);
    }

    @Test
    @DisplayName("Attack: Bit-flip is REJECTED with TAMPER event in HYBRID mode")
    void testBitFlip_RejectedWithTamperEvent_Hybrid() throws Exception {
        setupSession(ChatMode.HYBRID);
        clientService.sendMessage("Post-quantum payload seq=0");
        Thread.sleep(100);

        int initialEventCount = EventLog.getInstance().getEvents().size();

        attackerService.flipBit();
        Thread.sleep(150);

        List<ChatMessageRecord> received = serverService.getReceivedMessages();
        assertThat(received).hasSize(2);
        assertThat(received.get(1).status()).contains("REJECTED");
        assertThat(received.get(1).guardFired()).isEqualTo("TamperGuard");

        DetectionEvent lastEvent = EventLog.getInstance().getLastEvent();
        assertThat(lastEvent.attackType()).isEqualTo(DetectionEvent.AttackType.TAMPER);
    }

    // ── 3. DOWNGRADE ATTACK TEST ───────────────────────────────────────────

    @Test
    @DisplayName("Attack: Downgrade succeeds against CLASSICAL-VULNERABLE server")
    void testDowngrade_SucceedsInVulnerable() throws Exception {
        // Start server in vulnerable classical mode
        serverService = new ChatLabServerService(0);
        serverService.start(0, ChatMode.CLASSICAL_VULNERABLE);
        int serverPort = serverService.getTcpPort();

        // Start attacker proxy with stripHybrid enabled
        attackerService = new ChatLabAttackerService(0, serverPort);
        attackerService.start(0, serverPort);
        attackerService.setStripHybrid(true);
        int proxyPort = attackerService.getListenPort();

        clientService = new ChatLabClientService(proxyPort);
        // Client connects offering CLASSICAL without pinning (vulnerable client)
        clientService.connect("127.0.0.1", proxyPort, ChatMode.CLASSICAL_VULNERABLE, null);

        assertThat(clientService.isConnected()).isTrue();
        assertThat(clientService.getChosenSuite()).isEqualTo("CLASSICAL");
        assertThat(attackerService.getActionLog()).anyMatch(a ->
                a.action().equals("STRIP_HYBRID") && a.detail().contains("BEFORE: [HYBRID, CLASSICAL] AFTER: [CLASSICAL] Handshake accepted: true")
        );
    }

    @Test
    @DisplayName("Attack: Downgrade is BLOCKED against HYBRID server")
    void testDowngrade_BlockedInHybrid() throws Exception {
        // Start server in HYBRID mode
        serverService = new ChatLabServerService(0);
        serverService.start(0, ChatMode.HYBRID);
        int serverPort = serverService.getTcpPort();

        // Start attacker proxy with stripHybrid active
        attackerService = new ChatLabAttackerService(0, serverPort);
        attackerService.start(0, serverPort);
        attackerService.setStripHybrid(true);
        int proxyPort = attackerService.getListenPort();

        clientService = new ChatLabClientService(proxyPort);
        clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());

        // Handshake MUST fail because proxy stripped HYBRID and server policy rejects classical
        try {
            clientService.connect("127.0.0.1", proxyPort, ChatMode.HYBRID, null);
        } catch (Exception ignored) {}

        assertThat(clientService.isConnected()).isFalse();
        assertThat(clientService.getConnectionStatus()).isEqualTo("FAILED");
    }

    // ── 4. MITM ATTACK TEST ────────────────────────────────────────────────

    @Test
    @DisplayName("Attack: MITM sees DECRYPTED PLAINTEXT in CLASSICAL-VULNERABLE mode")
    void testMitm_PlaintextVisibleInVulnerableMode() throws Exception {
        serverService = new ChatLabServerService(0);
        serverService.start(0, ChatMode.CLASSICAL_VULNERABLE);
        int serverPort = serverService.getTcpPort();

        attackerService = new ChatLabAttackerService(0, serverPort);
        attackerService.start(0, serverPort);
        attackerService.setEnableMitm(true); // Active two-leg MITM
        int proxyPort = attackerService.getListenPort();

        clientService = new ChatLabClientService(proxyPort);
        clientService.connect("127.0.0.1", proxyPort, ChatMode.CLASSICAL_VULNERABLE, null);

        clientService.sendMessage("TOP-SECRET WIRE PAYLOAD 12345");
        Thread.sleep(150);

        // Verify Attacker decrypted and viewed genuine plaintext!
        List<CapturedTrafficRecord> traffic = attackerService.getCapturedTraffic();
        assertThat(traffic).isNotEmpty();

        boolean plaintextFound = traffic.stream().anyMatch(t ->
                t.attackerView() != null && t.attackerView().contains("TOP-SECRET WIRE PAYLOAD 12345")
        );
        assertThat(plaintextFound)
                .as("In CLASSICAL-VULNERABLE mode, Mallory MUST successfully decrypt and observe genuine plaintext")
                .isTrue();
    }

    @Test
    @DisplayName("Attack: MITM FAILS in CLASSICAL-HARDENED mode (client detects untrusted key)")
    void testMitm_FailsInHardenedMode() throws Exception {
        serverService = new ChatLabServerService(0);
        serverService.start(0, ChatMode.CLASSICAL_HARDENED);
        int serverPort = serverService.getTcpPort();

        attackerService = new ChatLabAttackerService(0, serverPort);
        attackerService.start(0, serverPort);
        attackerService.setEnableMitm(true); // Active two-leg MITM
        int proxyPort = attackerService.getListenPort();

        clientService = new ChatLabClientService(proxyPort);
        // Client pins Bob's legitimate server key
        clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());

        // Connect attempt MUST fail because Mallory's fake key is rejected by Alice's pinned key check
        try {
            clientService.connect("127.0.0.1", proxyPort, ChatMode.CLASSICAL_HARDENED, null);
        } catch (Exception ignored) {}

        assertThat(clientService.isConnected()).isFalse();
        assertThat(clientService.getConnectionStatus()).isEqualTo("FAILED");

        // Attacker captured traffic must NOT contain decrypted plaintext
        List<CapturedTrafficRecord> traffic = attackerService.getCapturedTraffic();
        boolean hasPlaintext = traffic.stream().anyMatch(t ->
                t.attackerView() != null && t.attackerView().startsWith("[MITM Intercepted Plaintext]: \"TOP-SECRET")
        );
        assertThat(hasPlaintext).isFalse();
    }

    private void setupSession(String mode) throws Exception {
        serverService = new ChatLabServerService(0);
        serverService.start(0, mode);
        int serverPort = serverService.getTcpPort();

        attackerService = new ChatLabAttackerService(0, serverPort);
        attackerService.start(0, serverPort);
        int proxyPort = attackerService.getListenPort();

        clientService = new ChatLabClientService(proxyPort);
        if (ChatMode.HYBRID.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
        } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
        }

        clientService.connect("127.0.0.1", proxyPort, mode, null);
    }
}
