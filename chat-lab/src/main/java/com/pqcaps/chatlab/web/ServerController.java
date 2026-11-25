package com.pqcaps.chatlab.web;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.chatlab.ChatMode;
import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.chatlab.service.ChatLabAttackerService;
import com.pqcaps.chatlab.service.ChatLabClientService;
import com.pqcaps.chatlab.service.ChatLabServerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST and SSE endpoints for Bob's Server role (:8083).
 */
@RestController
@RequestMapping("/api/server")
public class ServerController {

    private final ChatLabServerService serverService;
    private final ChatLabSseService sseService;
    private final ChatLabClientService clientService;
    private final ChatLabAttackerService attackerService;

    @Autowired
    public ServerController(
            ChatLabServerService serverService,
            ChatLabSseService sseService,
            @Autowired(required = false) ChatLabClientService clientService,
            @Autowired(required = false) ChatLabAttackerService attackerService) {
        this.serverService = serverService;
        this.sseService = sseService;
        this.clientService = clientService;
        this.attackerService = attackerService;

        // Hook SSE listeners
        serverService.addMessageListener(msg -> sseService.broadcastServer("server-message", msg));
        serverService.addEventListener(ev -> sseService.broadcastServer("detection-event", ev));
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        Map<String, Object> res = new HashMap<>();
        res.put("running", serverService.isRunning());
        res.put("mode", serverService.getCurrentMode());
        res.put("rejectClassical", serverService.isRejectClassical());
        res.put("tcpPort", serverService.getTcpPort());
        res.put("messageCount", serverService.getReceivedMessages().size());
        res.put("messages", serverService.getReceivedMessages());
        res.put("eventCount", serverService.getDetectionEvents().size());
        res.put("events", serverService.getDetectionEvents());
        return res;
    }

    @GetMapping("/reject-classical")
    public Map<String, Boolean> getRejectClassical() {
        return Map.of("rejectClassical", serverService.isRejectClassical());
    }

    @PostMapping("/reject-classical")
    public Map<String, Boolean> setRejectClassical(@RequestBody(required = false) Map<String, Boolean> body) {
        boolean reject = (body != null && body.containsKey("rejectClassical")) ? body.get("rejectClassical") : true;
        serverService.setRejectClassical(reject);
        sseService.broadcastServer("policy-change", Map.of("rejectClassical", reject));
        return Map.of("rejectClassical", serverService.isRejectClassical());
    }

    @GetMapping("/mode")
    public Map<String, String> getMode() {
        return Map.of("mode", serverService.getCurrentMode());
    }

    @PostMapping("/mode")
    public Map<String, String> setMode(@RequestBody(required = false) Map<String, String> body) {
        String mode = (body != null && body.containsKey("mode")) ? body.get("mode") : "HYBRID";
        serverService.setMode(mode);
        sseService.broadcastServer("mode-change", Map.of("mode", serverService.getCurrentMode()));
        return Map.of("mode", serverService.getCurrentMode());
    }

    @GetMapping("/messages")
    public List<ChatMessageRecord> getMessages() {
        return serverService.getReceivedMessages();
    }

    @PostMapping("/send")
    public ResponseEntity<?> sendServerMessage(@RequestBody Map<String, String> body) {
        String message = body != null ? body.get("message") : null;
        if (message == null || message.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Message cannot be empty"));
        }
        try {
            if (!serverService.hasActiveClient() || (clientService != null && !clientService.isConnected())) {
                if (!serverService.isRunning()) {
                    serverService.start();
                }
                if (attackerService != null && !attackerService.isRunning()) {
                    attackerService.start();
                }
                if (clientService != null) {
                    String mode = serverService.getCurrentMode();
                    if (ChatMode.HYBRID.equalsIgnoreCase(mode)) {
                        clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
                    } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
                        clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
                    }
                    int targetPort = (attackerService != null) ? attackerService.getListenPort() : serverService.getTcpPort();
                    clientService.connect(HostValidator.LOCALHOST_IP, targetPort, mode, null);
                }
            }
            ChatMessageRecord record = serverService.sendServerMessage(message);
            return ResponseEntity.ok(record);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to send: " + e.getMessage()));
        }
    }

    @GetMapping("/events")
    public List<DetectionEvent> getEvents() {
        return serverService.getDetectionEvents();
    }

    @PostMapping("/start")
    public ResponseEntity<?> start(@RequestBody(required = false) Map<String, Object> body) {
        int port = serverService.getTcpPort();
        String mode = serverService.getCurrentMode();
        if (body != null) {
            if (body.containsKey("port")) port = Integer.parseInt(String.valueOf(body.get("port")));
            if (body.containsKey("mode")) mode = String.valueOf(body.get("mode"));
        }
        try {
            serverService.start(port, mode);
            sseService.broadcastServer("server-status", Map.of("running", true, "port", serverService.getTcpPort(), "mode", serverService.getCurrentMode()));
            return ResponseEntity.ok(Map.of("running", true, "port", serverService.getTcpPort(), "mode", serverService.getCurrentMode()));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to start server: " + e.getMessage()));
        }
    }

    @PostMapping("/stop")
    public Map<String, Object> stop() {
        serverService.stop();
        sseService.broadcastServer("server-status", Map.of("running", false));
        return Map.of("running", false);
    }

    @PostMapping("/reset")
    public Map<String, Object> reset() {
        serverService.reset();
        sseService.broadcastServer("reset", Map.of("status", "RESET"));
        return Map.of("status", "RESET");
    }

    @GetMapping("/public-key")
    public Map<String, String> getPublicKeys() {
        String mldsa = Base64.getEncoder().encodeToString(serverService.getServerIdentityMlDsaPublic().getEncoded());
        String rsa = Base64.getEncoder().encodeToString(serverService.getServerIdentityRsaPublic().getEncoded());
        return Map.of(
                "mldsaPublicKey", mldsa,
                "rsaPublicKey", rsa
        );
    }

    @GetMapping("/stream")
    public SseEmitter stream() {
        return sseService.registerServerEmitter();
    }
}
