package com.pqcaps.chatlab.web;

import com.pqcaps.chatlab.ChatMode;
import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.chatlab.model.HandshakeStepRecord;
import com.pqcaps.chatlab.service.ChatLabAttackerService;
import com.pqcaps.chatlab.service.ChatLabClientService;
import com.pqcaps.chatlab.service.ChatLabServerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST and SSE endpoints for Alice's Client role (:8081).
 */
@RestController
@RequestMapping("/api/client")
public class ClientController {

    private final ChatLabClientService clientService;
    private final ChatLabSseService sseService;
    private final ChatLabServerService serverService;
    private final ChatLabAttackerService attackerService;

    @Autowired
    public ClientController(
            ChatLabClientService clientService,
            ChatLabSseService sseService,
            @Autowired(required = false) ChatLabServerService serverService,
            @Autowired(required = false) ChatLabAttackerService attackerService) {
        this.clientService = clientService;
        this.sseService = sseService;
        this.serverService = serverService;
        this.attackerService = attackerService;

        // Hook SSE listeners
        clientService.addStepListener(step -> sseService.broadcastClient("handshake-step", step));
        clientService.addMessageListener(msg -> sseService.broadcastClient("chat-message", msg));
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        Map<String, Object> res = new HashMap<>();
        res.put("status", clientService.getConnectionStatus());
        res.put("connected", clientService.isConnected());
        res.put("mode", clientService.getCurrentMode());
        res.put("chosenSuite", clientService.getChosenSuite());
        res.put("keyPinned", clientService.isKeyPinned());
        res.put("lastError", clientService.getLastError() != null ? clientService.getLastError() : "");
        res.put("targetPort", clientService.getTargetPort());
        res.put("stepCount", clientService.getHandshakeSteps().size());
        res.put("steps", clientService.getHandshakeSteps());
        res.put("messageCount", clientService.getChatHistory().size());
        res.put("history", clientService.getChatHistory());
        return res;
    }

    @GetMapping("/steps")
    public List<HandshakeStepRecord> getSteps() {
        return clientService.getHandshakeSteps();
    }

    @GetMapping("/history")
    public List<ChatMessageRecord> getHistory() {
        return clientService.getChatHistory();
    }

    @PostMapping("/mode")
    public Map<String, Object> setMode(@RequestBody(required = false) Map<String, String> body) {
        String mode = (body != null && body.containsKey("mode")) ? body.get("mode") : "HYBRID";
        clientService.setMode(mode);
        sseService.broadcastClient("mode-change", Map.of("mode", clientService.getCurrentMode()));
        return Map.of("mode", clientService.getCurrentMode());
    }

    @PostMapping("/connect")
    public ResponseEntity<?> connect(@RequestBody(required = false) Map<String, Object> body) {
        String host = HostValidator.LOCALHOST_IP;
        int port = clientService.getTargetPort();
        String mode = clientService.getCurrentMode();

        if (body != null) {
            if (body.containsKey("host")) {
                host = String.valueOf(body.get("host"));
                HostValidator.validateHost(host);
            }
            if (body.containsKey("port")) {
                port = Integer.parseInt(String.valueOf(body.get("port")));
            }
            if (body.containsKey("mode")) {
                mode = String.valueOf(body.get("mode"));
            }
        }

        try {
            if (serverService != null) {
                if (!serverService.isRunning()) {
                    serverService.start();
                }
                serverService.setMode(mode);
                if (ChatMode.HYBRID.equalsIgnoreCase(mode)) {
                    clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
                } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
                    clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
                } else {
                    clientService.setPinnedServerKeyMlDsa(null);
                    clientService.setPinnedServerKeyRsa(null);
                }
            }
            if (attackerService != null) {
                if (serverService != null) {
                    attackerService.setTargetPort(serverService.getTcpPort());
                }
                if (!attackerService.isRunning()) {
                    attackerService.start();
                }
            }
            clientService.connect(host, port, mode, null);
            sseService.broadcastClient("connection-status", Map.of(
                    "status", "CONNECTED",
                    "chosenSuite", clientService.getChosenSuite(),
                    "keyPinned", clientService.isKeyPinned()
            ));
            return ResponseEntity.ok(Map.of(
                    "status", "CONNECTED",
                    "chosenSuite", clientService.getChosenSuite(),
                    "keyPinned", clientService.isKeyPinned()
            ));
        } catch (Exception e) {
            sseService.broadcastClient("connection-status", Map.of(
                    "status", "FAILED",
                    "error", "handshake failed"
            ));
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "FAILED",
                    "error", "handshake failed" // Generic error message, never internal details
            ));
        }
    }

    @PostMapping("/send")
    public ResponseEntity<?> sendMessage(@RequestBody Map<String, String> body) {
        String message = body != null ? body.get("message") : null;
        if (message == null || message.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Message cannot be empty"));
        }

        try {
            if (!clientService.isConnected() || clientService.isSocketClosed()) {
                connect(null);
            }
            ChatMessageRecord record = clientService.sendMessage(message);
            return ResponseEntity.ok(record);
        } catch (Exception e) {
            try {
                connect(null);
                ChatMessageRecord record = clientService.sendMessage(message);
                return ResponseEntity.ok(record);
            } catch (Exception retryEx) {
                return ResponseEntity.badRequest().body(Map.of("error", "Failed to send message: " + retryEx.getMessage()));
            }
        }
    }

    @PostMapping("/disconnect")
    public Map<String, Object> disconnect() {
        clientService.disconnect();
        sseService.broadcastClient("connection-status", Map.of("status", "DISCONNECTED"));
        return Map.of("status", "DISCONNECTED");
    }

    @PostMapping("/reset")
    public Map<String, Object> reset() {
        clientService.reset();
        sseService.broadcastClient("reset", Map.of("status", "RESET"));
        return Map.of("status", "RESET");
    }

    @GetMapping("/stream")
    public SseEmitter stream() {
        return sseService.registerClientEmitter();
    }
}
