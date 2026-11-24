package com.pqcaps.chatlab.web;

import com.pqcaps.attack.EventLog;
import com.pqcaps.chatlab.ChatMode;
import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.service.ChatLabAttackerService;
import com.pqcaps.chatlab.service.ChatLabClientService;
import com.pqcaps.chatlab.service.ChatLabServerService;
import com.pqcaps.chatlab.service.GuidedDemoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for the Chat Lab Hub (:8090).
 * Orchestrates global control actions and executes guided attack demonstrations
 * across Alice (Client), Mallory (Attacker Proxy), and Bob (Server) over real localhost TCP sockets.
 */
@RestController
@RequestMapping("/api/hub")
public class HubController {

    private static final Logger log = LoggerFactory.getLogger(HubController.class);

    private final ChatLabClientService clientService;
    private final ChatLabAttackerService attackerService;
    private final ChatLabServerService serverService;
    private final GuidedDemoService guidedDemoService;

    public HubController(
            ChatLabClientService clientService,
            ChatLabAttackerService attackerService,
            ChatLabServerService serverService,
            GuidedDemoService guidedDemoService) {
        this.clientService = clientService;
        this.attackerService = attackerService;
        this.serverService = serverService;
        this.guidedDemoService = guidedDemoService;
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        return Map.of(
                "globalMode", clientService.getCurrentMode(),
                "client", Map.of(
                        "status", clientService.getConnectionStatus(),
                        "connected", clientService.isConnected(),
                        "mode", clientService.getCurrentMode(),
                        "chosenSuite", clientService.getChosenSuite(),
                        "keyPinned", clientService.isKeyPinned()
                ),
                "attacker", Map.of(
                        "running", attackerService.isRunning(),
                        "paused", attackerService.isPaused(),
                        "stripHybrid", attackerService.isStripHybrid(),
                        "enableMitm", attackerService.isEnableMitm(),
                        "listenPort", attackerService.getListenPort(),
                        "targetPort", attackerService.getTargetPort()
                ),
                "server", Map.of(
                        "running", serverService.isRunning(),
                        "mode", serverService.getCurrentMode(),
                        "rejectClassical", serverService.isRejectClassical(),
                        "tcpPort", serverService.getTcpPort(),
                        "messages", serverService.getReceivedMessages().size(),
                        "events", serverService.getDetectionEvents().size()
                )
        );
    }

    @PostMapping("/mode")
    public Map<String, Object> setMode(@RequestBody(required = false) Map<String, String> body) {
        String mode = (body != null && body.containsKey("mode")) ? body.get("mode") : "HYBRID";
        String normalizedMode = ChatMode.normalize(mode);

        clientService.setMode(normalizedMode);
        serverService.setMode(normalizedMode);

        syncPinnedKeys(normalizedMode);

        log.info("[ChatLab Hub] Global mode set to {}", normalizedMode);
        return getStatus();
    }

    @PostMapping("/connect")
    public Map<String, Object> connect() throws Exception {
        if (!serverService.isRunning()) {
            serverService.start();
        }
        attackerService.setTargetPort(serverService.getTcpPort());
        if (!attackerService.isRunning()) {
            attackerService.start();
        }

        String mode = clientService.getCurrentMode();
        syncPinnedKeys(mode);
        clientService.setTargetPort(attackerService.getListenPort());

        try {
            clientService.connect(HostValidator.LOCALHOST_IP, attackerService.getListenPort(), mode, null);
        } catch (Exception e) {
            log.warn("[ChatLab Hub] Connect resulted in expected handshake block/failure: {}", e.getMessage());
        }

        return getStatus();
    }

    @PostMapping("/reset-all")
    public Map<String, Object> resetAll() {
        clientService.disconnect();
        attackerService.reset();
        serverService.reset();
        EventLog.getInstance().clear();

        log.info("[ChatLab Hub] Reset all state across Alice, Mallory, and Bob");
        return getStatus();
    }

    @PostMapping("/stop-all")
    public Map<String, Object> stopAll() {
        clientService.disconnect();
        attackerService.stop();
        serverService.stop();

        log.info("[ChatLab Hub] Stopped all roles");
        return getStatus();
    }

    @PostMapping("/demo/{attack}")
    public ResponseEntity<?> runDemo(
            @PathVariable("attack") String attack,
            @RequestBody(required = false) Map<String, String> body) throws Exception {
        String reqMode = (body != null && body.containsKey("mode")) ? body.get("mode") : clientService.getCurrentMode();
        String mode = ChatMode.normalize(reqMode);

        log.info("[ChatLab Hub] Executing guided attack demo '{}' in mode {}", attack, mode);

        GuidedDemoService.DemoResult result = switch (attack.toLowerCase()) {
            case "replay" -> guidedDemoService.runReplayDemo(mode);
            case "downgrade" -> guidedDemoService.runDowngradeDemo(mode);
            case "mitm" -> guidedDemoService.runMitmDemo(mode);
            case "tamper" -> guidedDemoService.runTamperDemo(mode);
            default -> throw new IllegalArgumentException("Unknown guided demo attack: " + attack);
        };

        return ResponseEntity.ok(result);
    }

    private void syncPinnedKeys(String mode) {
        if (ChatMode.HYBRID.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
        } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
        } else {
            clientService.setPinnedServerKeyMlDsa(null);
            clientService.setPinnedServerKeyRsa(null);
        }
    }
}
