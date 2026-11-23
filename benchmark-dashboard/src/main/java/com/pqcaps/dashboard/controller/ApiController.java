package com.pqcaps.dashboard.controller;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attacklab.SecurityMatrixResult;
import com.pqcaps.dashboard.benchmark.BenchmarkReport;
import com.pqcaps.dashboard.service.ChatDemoService;
import com.pqcaps.dashboard.service.DashboardDataService;
import com.pqcaps.dashboard.service.HandshakeVisualizerService;
import com.pqcaps.dashboard.service.SimulatorService;
import com.pqcaps.scanner.ScanReport;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://127.0.0.1:8080")
public class ApiController {

    private final DashboardDataService dataService;
    private final HandshakeVisualizerService visualizerService;
    private final SimulatorService simulatorService;
    private final ChatDemoService chatDemoService;

    public ApiController(
            DashboardDataService dataService,
            HandshakeVisualizerService visualizerService,
            SimulatorService simulatorService,
            ChatDemoService chatDemoService) {
        this.dataService = dataService;
        this.visualizerService = visualizerService;
        this.simulatorService = simulatorService;
        this.chatDemoService = chatDemoService;
    }

    // ── Existing Endpoints ────────────────────────────────────────────────

    @GetMapping("/attacks")
    public List<SecurityMatrixResult> getAttacks() {
        return dataService.loadAttacks();
    }

    @GetMapping("/events")
    public List<DetectionEvent> getEvents(@RequestParam(value = "limit", defaultValue = "50") int limit) {
        return dataService.loadEvents(limit);
    }

    @GetMapping("/scan/{target}")
    public ScanReport getScanReport(@PathVariable("target") String target) {
        return dataService.loadScanReport(target);
    }

    @GetMapping("/benchmarks")
    public BenchmarkReport getBenchmarks() {
        return dataService.loadBenchmarks();
    }

    @GetMapping(value = "/events/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamEvents() {
        return dataService.registerEmitter();
    }

    @PostMapping("/demo/run-attacks")
    public List<SecurityMatrixResult> runAttacks() {
        return dataService.runAttacks();
    }

    // ── 1. Live Handshake Visualizer Endpoints ─────────────────────────────

    @GetMapping(value = "/handshake/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamHandshake(@RequestParam(value = "suite", defaultValue = "HYBRID") String suite) {
        if (!List.of("CLASSICAL", "HYBRID", "PQ_ONLY").contains(suite.toUpperCase())) {
            throw new IllegalArgumentException("Invalid suite: '" + suite + "'. Allowed: CLASSICAL, HYBRID, PQ_ONLY");
        }
        SseEmitter emitter = new SseEmitter(60_000L);
        visualizerService.streamHandshake(suite, emitter);
        return emitter;
    }

    @PostMapping("/handshake/run")
    public HandshakeVisualizerService.HandshakeVisualizerResult runHandshake(
            @RequestParam(value = "suite", defaultValue = "HYBRID") String suite) {
        if (!List.of("CLASSICAL", "HYBRID", "PQ_ONLY").contains(suite.toUpperCase())) {
            throw new IllegalArgumentException("Invalid suite: '" + suite + "'. Allowed: CLASSICAL, HYBRID, PQ_ONLY");
        }
        return visualizerService.executeHandshake(suite);
    }

    // ── 2. Attack Simulator Endpoint ──────────────────────────────────────

    public record SimulationRequest(String attack, String mode) {}

    @PostMapping("/simulator/run")
    public SimulatorService.AttackSimulationResponse runSimulation(
            @RequestBody(required = false) SimulationRequest body,
            @RequestParam(value = "attack", required = false) String attackParam,
            @RequestParam(value = "mode", required = false) String modeParam) {
        String attack = (body != null && body.attack() != null) ? body.attack() : attackParam;
        String mode = (body != null && body.mode() != null) ? body.mode() : modeParam;

        if (attack == null || attack.isBlank()) {
            throw new IllegalArgumentException("Attack parameter is required. Allowed: Downgrade, MITM, Replay, Nonce Reuse, Tampering");
        }
        if (mode == null || mode.isBlank()) {
            throw new IllegalArgumentException("Mode parameter is required. Allowed: CLASSICAL-VULNERABLE, CLASSICAL-HARDENED, HYBRID");
        }

        return simulatorService.runSimulation(attack, mode);
    }

    // ── 4. Scanner Run Endpoint ───────────────────────────────────────────

    @PostMapping("/scan/run")
    public ScanReport runScan(@RequestParam(value = "target", defaultValue = "vulnerable") String target) {
        if (!List.of("vulnerable", "migrated", "self").contains(target.toLowerCase())) {
            throw new IllegalArgumentException("Invalid scan target: '" + target + "'. Allowed: vulnerable, migrated, self");
        }
        return dataService.runScan(target);
    }

    // ── 5. Secure Chat Demo Endpoints ─────────────────────────────────────

    @PostMapping("/chat/init")
    public Map<String, String> initChat(@RequestParam(value = "mode", defaultValue = "HYBRID") String mode) {
        if (!List.of("CLASSICAL-VULNERABLE", "CLASSICAL-HARDENED", "HYBRID").contains(mode.toUpperCase())) {
            throw new IllegalArgumentException("Invalid chat mode: '" + mode + "'. Allowed: CLASSICAL-VULNERABLE, CLASSICAL-HARDENED, HYBRID");
        }
        chatDemoService.initSession(mode);
        String resolvedMode = chatDemoService.getCurrentMode() != null ? chatDemoService.getCurrentMode() : mode.toUpperCase();
        return Map.of("status", "INITIALIZED", "mode", resolvedMode);
    }

    public record ChatMessageRequest(String message) {}

    @PostMapping("/chat/send")
    public ChatDemoService.ChatSendResult sendChatMessage(
            @RequestBody(required = false) ChatMessageRequest body,
            @RequestParam(value = "message", required = false) String messageParam) {
        String msg = (body != null && body.message() != null) ? body.message() : messageParam;
        if (msg == null || msg.trim().isEmpty()) {
            throw new IllegalArgumentException("Message text cannot be empty");
        }
        return chatDemoService.sendMessage(msg.trim());
    }

    @PostMapping("/chat/attacker/replay")
    public ChatDemoService.AttackerActionResult replayMessage() {
        return chatDemoService.replayLastMessage();
    }

    @PostMapping("/chat/attacker/flip-bit")
    public ChatDemoService.AttackerActionResult flipBit() {
        return chatDemoService.flipBit();
    }
}
