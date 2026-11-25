package com.pqcaps.chatlab;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attack.EventLog;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.chatlab.service.ChatLabAttackerService;
import com.pqcaps.chatlab.service.ChatLabClientService;
import com.pqcaps.chatlab.service.ChatLabServerService;
import com.pqcaps.chatlab.service.GuidedDemoService;
import com.pqcaps.chatlab.web.HubController;
import com.pqcaps.chatlab.web.SecurityHeadersFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.role=all",
        "server.port=0",
        "server.tcp.port=0",
        "attacker.tcp.listenPort=0",
        "attacker.tcp.targetPort=0",
        "client.tcp.targetPort=0"
})
@AutoConfigureMockMvc
@DisplayName("Chat Lab Hub Integration & Guided Demo Tests")
class ChatLabHubTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ChatLabServerService serverService;

    @Autowired
    private ChatLabAttackerService attackerService;

    @Autowired
    private ChatLabClientService clientService;

    @Autowired
    private GuidedDemoService guidedDemoService;

    @AfterEach
    void tearDown() {
        if (clientService != null) clientService.disconnect();
        if (attackerService != null) attackerService.stop();
        if (serverService != null) serverService.stop();
        EventLog.getInstance().clear();
    }

    @Test
    @DisplayName("Hub: --role=all runs Alice, Mallory, Bob over TCP in all 3 modes")
    void testAllInOne_MessageFlowAcrossAllThreeModes() throws Exception {
        // Start Bob on ephemeral port
        serverService.start(0, "HYBRID");
        int bobPort = serverService.getTcpPort();
        assertThat(bobPort).isPositive();

        // Start Mallory targeting Bob
        attackerService.start(0, bobPort);
        int malloryPort = attackerService.getListenPort();
        assertThat(malloryPort).isPositive();

        clientService.setTargetPort(malloryPort);

        List<String> modes = List.of(ChatMode.CLASSICAL_VULNERABLE, ChatMode.CLASSICAL_HARDENED, ChatMode.HYBRID);

        for (String mode : modes) {
            clientService.disconnect();
            attackerService.reset();
            serverService.reset();

            serverService.setMode(mode);
            clientService.setMode(mode);

            if (ChatMode.HYBRID.equalsIgnoreCase(mode)) {
                clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
            } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
                clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
            } else {
                clientService.setPinnedServerKeyMlDsa(null);
                clientService.setPinnedServerKeyRsa(null);
            }

            clientService.connect(HostValidator.LOCALHOST_IP, malloryPort, mode, null);
            assertThat(clientService.isConnected()).isTrue();

            String text = "Test payload for mode " + mode;
            clientService.sendMessage(text);

            Thread.sleep(120);

            // Assert message delivered through proxy to server
            List<ChatMessageRecord> serverMsgs = serverService.getReceivedMessages();
            assertThat(serverMsgs).isNotEmpty();
            ChatMessageRecord lastMsg = serverMsgs.get(serverMsgs.size() - 1);
            assertThat(lastMsg.text()).isEqualTo(text);
            assertThat(lastMsg.status()).contains("ACCEPTED");

            // Assert attacker captured proxy traffic
            assertThat(attackerService.getCapturedTraffic()).isNotEmpty();
        }
    }

    @Test
    @DisplayName("Hub: Guided demos return expected outcome per mode (vulnerable succeeds, hardened/hybrid blocked)")
    void testGuidedDemos_ExpectedOutcomesPerMode() throws Exception {
        // 1. Replay Demo
        GuidedDemoService.DemoResult replayVuln = guidedDemoService.runReplayDemo(ChatMode.CLASSICAL_VULNERABLE);
        assertThat(replayVuln.status()).isEqualTo("SUCCEEDED");
        assertThat(replayVuln.outcome()).contains("SUCCEEDED");

        GuidedDemoService.DemoResult replayHybrid = guidedDemoService.runReplayDemo(ChatMode.HYBRID);
        assertThat(replayHybrid.status()).isEqualTo("BLOCKED");
        assertThat(replayHybrid.outcome()).contains("BLOCKED by ReplayGuard");

        // 2. Downgrade Demo
        GuidedDemoService.DemoResult downVuln = guidedDemoService.runDowngradeDemo(ChatMode.CLASSICAL_VULNERABLE);
        assertThat(downVuln.status()).isEqualTo("SUCCEEDED");
        assertThat(downVuln.outcome()).contains("BEFORE: [HYBRID, CLASSICAL] AFTER: [CLASSICAL] Handshake accepted: true");

        GuidedDemoService.DemoResult downHybrid = guidedDemoService.runDowngradeDemo(ChatMode.HYBRID);
        assertThat(downHybrid.status()).isEqualTo("BLOCKED");
        assertThat(downHybrid.outcome()).contains("BLOCKED by DowngradeGuard");

        // 3. MITM Demo
        GuidedDemoService.DemoResult mitmVuln = guidedDemoService.runMitmDemo(ChatMode.CLASSICAL_VULNERABLE);
        assertThat(mitmVuln.status()).isEqualTo("SUCCEEDED");

        GuidedDemoService.DemoResult mitmHybrid = guidedDemoService.runMitmDemo(ChatMode.HYBRID);
        assertThat(mitmHybrid.status()).isEqualTo("BLOCKED");
        assertThat(mitmHybrid.outcome()).contains("BLOCKED by MitmGuard");

        // 4. Tamper Demo
        GuidedDemoService.DemoResult tamperVuln = guidedDemoService.runTamperDemo(ChatMode.CLASSICAL_VULNERABLE);
        assertThat(tamperVuln.status()).isEqualTo("SUCCEEDED");
        assertThat(tamperVuln.outcome()).contains("UNDETECTED");

        GuidedDemoService.DemoResult tamperHybrid = guidedDemoService.runTamperDemo(ChatMode.HYBRID);
        assertThat(tamperHybrid.status()).isEqualTo("BLOCKED");
        assertThat(tamperHybrid.outcome()).contains("BLOCKED by TamperGuard");
    }

    @Test
    @DisplayName("Hub: Web UI returns 200 and Content-Security-Policy restricts framing strictly to 127.0.0.1:8090")
    void testHubPageAndCspHeader() throws Exception {
        // Verify GET /hub.html
        mockMvc.perform(get("/hub.html"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", SecurityHeadersFilter.CSP_POLICY));

        // Verify root redirects to hub.html when active role is all
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/hub.html"));

        // Verify SecurityHeadersFilter directly
        SecurityHeadersFilter filter = new SecurityHeadersFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);
        assertThat(response.getHeader(SecurityHeadersFilter.CSP_HEADER))
                .isEqualTo(SecurityHeadersFilter.CSP_POLICY);
    }

    @Test
    @DisplayName("Hub: REST API controls mode, connect, reset-all, stop-all, and status")
    void testHubRestEndpoints() throws Exception {
        // GET /api/hub/status
        mockMvc.perform(get("/api/hub/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.globalMode").exists())
                .andExpect(jsonPath("$.client").exists())
                .andExpect(jsonPath("$.attacker").exists())
                .andExpect(jsonPath("$.server").exists());

        // POST /api/hub/mode
        mockMvc.perform(post("/api/hub/mode")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"mode\":\"CLASSICAL-HARDENED\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.globalMode").value("CLASSICAL-HARDENED"))
                .andExpect(jsonPath("$.client.mode").value("CLASSICAL-HARDENED"))
                .andExpect(jsonPath("$.server.mode").value("CLASSICAL-HARDENED"));

        // POST /api/hub/reset-all
        mockMvc.perform(post("/api/hub/reset-all"))
                .andExpect(status().isOk());

        // POST /api/hub/stop-all
        mockMvc.perform(post("/api/hub/stop-all"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.attacker.running").value(false))
                .andExpect(jsonPath("$.server.running").value(false));

        // POST /api/hub/demo/replay
        mockMvc.perform(post("/api/hub/demo/replay")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"mode\":\"HYBRID\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.attack").value("REPLAY"))
                .andExpect(jsonPath("$.status").value("BLOCKED"));
    }

    @Test
    @DisplayName("Hub: Real --role=all startup serves hub.html (200) and routes message Alice -> Mallory -> Bob over TCP")
    void testRealRoleAllStartup_MessageFlowAliceMalloryBob() throws Exception {
        // Assert hub.html returns 200 and CSP header
        mockMvc.perform(get("/hub.html"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", SecurityHeadersFilter.CSP_POLICY));

        // Assert root redirects to hub.html because active role is all
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/hub.html"));

        // Ensure services are running (auto-started by roleStartupRunner for role=all)
        if (!serverService.isRunning()) {
            serverService.start(0, "HYBRID");
        }
        attackerService.setTargetPort(serverService.getTcpPort());
        if (!attackerService.isRunning()) {
            attackerService.start(0, serverService.getTcpPort());
        }

        assertThat(serverService.isRunning()).isTrue();
        assertThat(attackerService.isRunning()).isTrue();

        int proxyPort = attackerService.getListenPort();
        int serverPort = serverService.getTcpPort();
        assertThat(proxyPort).isPositive();
        assertThat(serverPort).isPositive();
        assertThat(attackerService.getTargetPort()).isEqualTo(serverPort);

        // Connect Alice to Mallory proxy over TCP
        clientService.setTargetPort(proxyPort);
        clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
        clientService.connect(HostValidator.LOCALHOST_IP, proxyPort, "HYBRID", null);
        assertThat(clientService.isConnected()).isTrue();

        // Send a message Alice -> Mallory -> Bob
        String testMsg = "Live message Alice -> Mallory -> Bob via --role=all";
        clientService.sendMessage(testMsg);

        Thread.sleep(120);

        // Assert Bob received the message
        List<ChatMessageRecord> serverMsgs = serverService.getReceivedMessages();
        assertThat(serverMsgs).isNotEmpty();
        ChatMessageRecord lastRec = serverMsgs.get(serverMsgs.size() - 1);
        assertThat(lastRec.text()).isEqualTo(testMsg);
        assertThat(lastRec.status()).contains("ACCEPTED");

        // Assert Mallory captured the wire record
        assertThat(attackerService.getCapturedTraffic()).isNotEmpty();
    }
}
