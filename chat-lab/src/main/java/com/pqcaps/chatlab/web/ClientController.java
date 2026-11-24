package com.pqcaps.chatlab.web;

import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import com.pqcaps.chatlab.model.HandshakeStepRecord;
import com.pqcaps.chatlab.service.ChatLabClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

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

    public ClientController(ChatLabClientService clientService, ChatLabSseService sseService) {
        this.clientService = clientService;
        this.sseService = sseService;

        // Hook SSE listeners
        clientService.addStepListener(step -> sseService.broadcastClient("handshake-step", step));
        clientService.addMessageListener(msg -> sseService.broadcastClient("chat-message", msg));
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        return Map.of(
                "status", clientService.getConnectionStatus(),
                "connected", clientService.isConnected(),
                "mode", clientService.getCurrentMode(),
                "chosenSuite", clientService.getChosenSuite(),
                "keyPinned", clientService.isKeyPinned(),
                "lastError", clientService.getLastError() != null ? clientService.getLastError() : "",
                "targetPort", clientService.getTargetPort(),
                "stepCount", clientService.getHandshakeSteps().size(),
                "messageCount", clientService.getChatHistory().size()
        );
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
                    "error", "Handshake failed"
            ));
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "FAILED",
                    "error", "Handshake failed" // Generic error message, never internal details
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
            ChatMessageRecord record = clientService.sendMessage(message);
            return ResponseEntity.ok(record);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Failed to send message: " + e.getMessage()));
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
