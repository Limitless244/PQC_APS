package com.pqcaps.chatlab;

import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.chatlab.service.ChatLabAttackerService;
import com.pqcaps.chatlab.service.ChatLabClientService;
import com.pqcaps.chatlab.service.ChatLabServerService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ChatLabIntegrationTest {

    private ChatLabServerService serverService;
    private ChatLabAttackerService attackerService;
    private ChatLabClientService clientService;

    @AfterEach
    void tearDown() {
        if (clientService != null) clientService.disconnect();
        if (attackerService != null) attackerService.stop();
        if (serverService != null) serverService.stop();
    }

    @Test
    @DisplayName("Integration: Message delivers through live proxy in CLASSICAL-VULNERABLE mode")
    void testMessageFlow_ClassicalVulnerable() throws Exception {
        setupAndSendMessage(ChatMode.CLASSICAL_VULNERABLE, "Transfer 500 via Vulnerable Baseline");

        assertThat(clientService.isConnected()).isTrue();
        assertThat(clientService.getChosenSuite()).isEqualTo("CLASSICAL");

        // Assert Server received message
        assertThat(serverService.getReceivedMessages()).isNotEmpty();
        ChatMessageRecord serverMsg = serverService.getReceivedMessages().get(0);
        assertThat(serverMsg.text()).isEqualTo("Transfer 500 via Vulnerable Baseline");
        assertThat(serverMsg.status()).isEqualTo("ACCEPTED");

        // Assert Attacker captured the wire record
        assertThat(attackerService.getCapturedTraffic()).isNotEmpty();
    }

    @Test
    @DisplayName("Integration: Message delivers through live proxy in CLASSICAL-HARDENED mode")
    void testMessageFlow_ClassicalHardened() throws Exception {
        setupAndSendMessage(ChatMode.CLASSICAL_HARDENED, "Transfer 500 via Hardened Classical");

        assertThat(clientService.isConnected()).isTrue();
        assertThat(clientService.getChosenSuite()).isEqualTo("CLASSICAL");
        assertThat(clientService.isKeyPinned()).isTrue();

        // Assert Server received message
        assertThat(serverService.getReceivedMessages()).isNotEmpty();
        ChatMessageRecord serverMsg = serverService.getReceivedMessages().get(0);
        assertThat(serverMsg.text()).isEqualTo("Transfer 500 via Hardened Classical");
        assertThat(serverMsg.status()).contains("ACCEPTED");
    }

    @Test
    @DisplayName("Integration: Message delivers through live proxy in HYBRID post-quantum mode")
    void testMessageFlow_Hybrid() throws Exception {
        setupAndSendMessage(ChatMode.HYBRID, "Confidential payload via Post-Quantum Hybrid");

        assertThat(clientService.isConnected()).isTrue();
        assertThat(clientService.getChosenSuite()).isEqualTo("HYBRID");
        assertThat(clientService.isKeyPinned()).isTrue();

        // Assert Server received message
        assertThat(serverService.getReceivedMessages()).isNotEmpty();
        ChatMessageRecord serverMsg = serverService.getReceivedMessages().get(0);
        assertThat(serverMsg.text()).isEqualTo("Confidential payload via Post-Quantum Hybrid");
        assertThat(serverMsg.status()).contains("ACCEPTED");
    }

    private void setupAndSendMessage(String mode, String messageText) throws Exception {
        // 1. Start Server on ephemeral free port (0)
        serverService = new ChatLabServerService(0);
        serverService.start(0, mode);
        int serverPort = serverService.getTcpPort();

        // 2. Start Attacker Proxy on ephemeral free port (0), targeting serverPort
        attackerService = new ChatLabAttackerService(0, serverPort);
        attackerService.start(0, serverPort);
        int proxyPort = attackerService.getListenPort();

        // 3. Configure Client to connect to Attacker Proxy port
        clientService = new ChatLabClientService(proxyPort);
        if (ChatMode.HYBRID.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
        } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
        }

        clientService.connect("127.0.0.1", proxyPort, mode, null);
        clientService.sendMessage(messageText);

        // Allow background thread to process
        Thread.sleep(150);
    }
}
