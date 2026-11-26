package com.pqcaps.dashboard.controller;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attacklab.SecurityMatrixResult;
import com.pqcaps.common.HandshakeStepEvent;
import com.pqcaps.dashboard.benchmark.BenchmarkReport;
import com.pqcaps.dashboard.benchmark.BenchmarkRunner;
import com.pqcaps.dashboard.service.ChatDemoService;
import com.pqcaps.dashboard.service.DashboardDataService;
import com.pqcaps.dashboard.service.HandshakeVisualizerService;
import com.pqcaps.dashboard.service.SimulatorService;
import com.pqcaps.scanner.ScanReport;
import com.pqcaps.scanner.ScanSummary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = {ApiController.class, GlobalExceptionHandler.class})
@DisplayName("API Controller Tests")
@SuppressWarnings("null") // Hamcrest matchers and MediaType constants are unannotated for Spring @NonNullApi MockMvc DSL
class ApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private DashboardDataService dataService;

    @MockitoBean
    private HandshakeVisualizerService visualizerService;

    @MockitoBean
    private SimulatorService simulatorService;

    @MockitoBean
    private ChatDemoService chatDemoService;

    // ── Existing Endpoints ────────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/attacks returns list of 15 matrix results")
    void getAttacks_returns15Results() throws Exception {
        List<SecurityMatrixResult> matrix = buildFakeMatrix(15);
        Mockito.when(dataService.loadAttacks()).thenReturn(matrix);

        mockMvc.perform(get("/api/attacks").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(15)));
    }

    @Test
    @DisplayName("GET /api/events?limit=5 returns at most 5 events")
    void getEvents_withLimit_returnsBoundedList() throws Exception {
        List<DetectionEvent> events = buildFakeEvents(3);
        Mockito.when(dataService.loadEvents(anyInt())).thenReturn(events);

        mockMvc.perform(get("/api/events").param("limit", "5").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)));
    }

    @Test
    @DisplayName("GET /api/scan/vulnerable returns report with grade F")
    void getScan_vulnerable_returnsGradeF() throws Exception {
        ScanReport report = buildFakeScanReport("F", 92, 5);
        Mockito.when(dataService.loadScanReport("vulnerable")).thenReturn(report);

        mockMvc.perform(get("/api/scan/vulnerable").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.grade", is("F")))
                .andExpect(jsonPath("$.summary.overallScore", is(92)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"vulnerable", "migrated", "self", "self-production", "self-tests"})
    @DisplayName("GET /api/scan/{target} returns 200 with score, grade and points")
    void getScan_allFiveTargets_returns200WithScoreGradeAndPoints(String target) throws Exception {
        ScanSummary summary = new ScanSummary(10, Map.of("HIGH", 2), 45, 60, "C", 50.0);
        ScanReport report = new ScanReport("scan-" + target, "Directory: " + target, Instant.now().toString(), summary, Collections.emptyList());
        Mockito.when(dataService.loadScanReport(target)).thenReturn(report);

        mockMvc.perform(get("/api/scan/" + target).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.overallScore", is(45)))
                .andExpect(jsonPath("$.summary.grade", is("C")))
                .andExpect(jsonPath("$.summary.riskPoints", is(60)));
    }

    @Test
    @DisplayName("GET /api/scan/unknown returns 400 JSON without stack trace")
    void getScan_unknownTarget_returns400Json() throws Exception {
        Mockito.when(dataService.loadScanReport("unknown"))
                .thenThrow(new IllegalArgumentException("Invalid scan target 'unknown'. Allowed targets: vulnerable, migrated, self"));

        mockMvc.perform(get("/api/scan/unknown").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$", not(hasKey("trace"))));
    }

    @Test
    @DisplayName("GET /api/benchmarks returns machine info and size metrics")
    void getBenchmarks_returnsMachineInfo() throws Exception {
        BenchmarkReport report = BenchmarkRunner.run(true);
        Mockito.when(dataService.loadBenchmarks()).thenReturn(report);

        mockMvc.perform(get("/api/benchmarks").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.machine").exists())
                .andExpect(jsonPath("$.machine.jdkVersion").isNotEmpty())
                .andExpect(jsonPath("$.sizes").isArray());
    }

    @Test
    @DisplayName("GET /api/test-summary returns dynamic test summary when available")
    void getTestSummary_whenAvailable_returnsSummary() throws Exception {
        Mockito.when(dataService.loadTestSummary()).thenReturn(Map.of(
                "available", true,
                "totalTests", 166,
                "passed", 166,
                "failures", 0,
                "errors", 0,
                "skipped", 0,
                "moduleCount", 10,
                "caption", "Across 10 modules"
        ));

        mockMvc.perform(get("/api/test-summary").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.available").value(true))
                .andExpect(jsonPath("$.totalTests").value(166))
                .andExpect(jsonPath("$.passed").value(166))
                .andExpect(jsonPath("$.caption").value("Across 10 modules"));
    }

    @Test
    @DisplayName("GET /api/test-summary returns available=false when file missing")
    void getTestSummary_whenMissing_returnsNotAvailable() throws Exception {
        Mockito.when(dataService.loadTestSummary()).thenReturn(Map.of("available", false));

        mockMvc.perform(get("/api/test-summary").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.available").value(false));
    }

    @Test
    @DisplayName("GET /api/events/stream returns text/event-stream content type")
    void getEventsStream_returnsSseContentType() throws Exception {
        Mockito.when(dataService.registerEmitter())
                .thenAnswer(inv -> {
                    SseEmitter emitter = new SseEmitter(100L);
                    emitter.complete();
                    return emitter;
                });

        mockMvc.perform(get("/api/events/stream"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM));
    }

    @Test
    @DisplayName("AsyncRequestTimeoutException on SSE endpoint produces no body and no exception")
    void sseEndpoint_onTimeout_returnsNoBodyAndNoException() throws Exception {
        Mockito.when(dataService.registerEmitter())
                .thenThrow(new org.springframework.web.context.request.async.AsyncRequestTimeoutException());

        mockMvc.perform(get("/api/events/stream").accept(MediaType.TEXT_EVENT_STREAM))
                .andExpect(status().isOk())
                .andExpect(content().string(""));
    }

    @Test
    @DisplayName("POST /api/demo/run-attacks returns 15 results")
    void runAttacks_returns15Rows() throws Exception {
        List<SecurityMatrixResult> matrix = buildFakeMatrix(15);
        Mockito.when(dataService.runAttacks()).thenReturn(matrix);

        mockMvc.perform(post("/api/demo/run-attacks").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(15)));
    }

    // ── 1. Handshake Visualizer Endpoints ──────────────────────────────────

    @Test
    @DisplayName("GET /api/handshake/stream with valid suite returns SSE stream")
    void streamHandshake_validSuite_returnsSse() throws Exception {
        Mockito.doAnswer(inv -> {
            SseEmitter emitter = inv.getArgument(1);
            try {
                emitter.send(SseEmitter.event().name("step").data(new HandshakeStepEvent("ClientHello", "CLIENT_TO_SERVER", 1356, "3a4b", "OK", Instant.now())));
                emitter.complete();
            } catch (Exception ignored) {}
            return null;
        }).when(visualizerService).streamHandshake(eq("HYBRID"), any(SseEmitter.class));

        mockMvc.perform(get("/api/handshake/stream").param("suite", "HYBRID"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM));
    }

    @Test
    @DisplayName("GET /api/handshake/stream with invalid suite returns 400 JSON")
    void streamHandshake_invalidSuite_returns400() throws Exception {
        mockMvc.perform(get("/api/handshake/stream").param("suite", "ROT13"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", containsString("ROT13")));
    }

    @Test
    @DisplayName("POST /api/handshake/run with valid suite returns result")
    void runHandshake_validSuite_returnsResult() throws Exception {
        HandshakeVisualizerService.HandshakeVisualizerResult fakeRes =
                new HandshakeVisualizerService.HandshakeVisualizerResult("HYBRID", Collections.<HandshakeStepEvent>emptyList(), 6433, 6098, 5000000L, 5.0, 0.0, "SECURE");
        Mockito.when(visualizerService.executeHandshake("HYBRID")).thenReturn(fakeRes);

        mockMvc.perform(post("/api/handshake/run").param("suite", "HYBRID"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.suite", is("HYBRID")))
                .andExpect(jsonPath("$.totalWireBytes", is(6433)))
                .andExpect(jsonPath("$.payloadBytes", is(6098)))
                .andExpect(jsonPath("$.outcome", is("SECURE")));
    }

    @Test
    @DisplayName("POST /api/handshake/run-x5 with valid suite returns 5 runs and mean/min stats")
    void runHandshakeX5_validSuite_returnsResult() throws Exception {
        HandshakeVisualizerService.HandshakeX5Result fakeRes =
                new HandshakeVisualizerService.HandshakeX5Result("HYBRID", List.of(5.0, 2.0, 1.8, 1.9, 1.8), 1.88, 1.80, 5.0, 6433, 6098);
        Mockito.when(visualizerService.executeHandshakeX5("HYBRID")).thenReturn(fakeRes);

        mockMvc.perform(post("/api/handshake/run-x5").param("suite", "HYBRID"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.suite", is("HYBRID")))
                .andExpect(jsonPath("$.meanLast4Millis", is(1.88)))
                .andExpect(jsonPath("$.minLast4Millis", is(1.80)))
                .andExpect(jsonPath("$.coldStartMillis", is(5.0)))
                .andExpect(jsonPath("$.totalWireBytes", is(6433)));
    }

    // ── 2. Attack Simulator Endpoints ─────────────────────────────────────

    @Test
    @DisplayName("POST /api/simulator/run with valid attack and mode returns simulation response")
    void runSimulator_valid_returnsResult() throws Exception {
        SimulatorService.AttackSimulationResponse fakeRes = new SimulatorService.AttackSimulationResponse(
                "Downgrade", "HYBRID", false, true, "DET-001",
                "ClientHello suites stripped -> blocked by ML-DSA signed transcript mismatch",
                "Downgrade explanation", "SignatureGuard (BLOCKED)",
                List.of("Step 1", "Step 2"), null
        );
        Mockito.when(simulatorService.runSimulation("Downgrade", "HYBRID")).thenReturn(fakeRes);

        mockMvc.perform(post("/api/simulator/run")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"attack\": \"Downgrade\", \"mode\": \"HYBRID\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.attack", is("Downgrade")))
                .andExpect(jsonPath("$.mode", is("HYBRID")))
                .andExpect(jsonPath("$.attackSucceeded", is(false)))
                .andExpect(jsonPath("$.defenceTriggered", is(true)));
    }

    @Test
    @DisplayName("POST /api/simulator/run with invalid attack returns 400")
    void runSimulator_invalidAttack_returns400() throws Exception {
        Mockito.when(simulatorService.runSimulation("SQL_INJECTION", "HYBRID"))
                .thenThrow(new IllegalArgumentException("Invalid attack name: 'SQL_INJECTION'"));

        mockMvc.perform(post("/api/simulator/run")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"attack\": \"SQL_INJECTION\", \"mode\": \"HYBRID\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Bad Request")));
    }

    @Test
    @DisplayName("POST /api/simulator/run with invalid mode returns 400")
    void runSimulator_invalidMode_returns400() throws Exception {
        Mockito.when(simulatorService.runSimulation("Downgrade", "INSECURE_RANDOM_MODE"))
                .thenThrow(new IllegalArgumentException("Invalid mode: 'INSECURE_RANDOM_MODE'"));

        mockMvc.perform(post("/api/simulator/run")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"attack\": \"Downgrade\", \"mode\": \"INSECURE_RANDOM_MODE\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Bad Request")));
    }

    // ── 4. Scanner Run Endpoint ───────────────────────────────────────────

    @Test
    @DisplayName("POST /api/scan/run with valid target returns updated ScanReport")
    void runScan_validTarget_returnsReport() throws Exception {
        ScanReport report = buildFakeScanReport("A", 0, 0);
        Mockito.when(dataService.runScan("migrated")).thenReturn(report);

        mockMvc.perform(post("/api/scan/run").param("target", "migrated"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.grade", is("A")))
                .andExpect(jsonPath("$.summary.overallScore", is(0)));
    }

    @Test
    @DisplayName("POST /api/scan/run with invalid target returns 400")
    void runScan_invalidTarget_returns400() throws Exception {
        Mockito.when(dataService.runScan("etc_passwd"))
                .thenThrow(new IllegalArgumentException("Invalid scan target: 'etc_passwd'"));

        mockMvc.perform(post("/api/scan/run").param("target", "etc_passwd"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Bad Request")));
    }

    // ── 5. Secure Chat Demo Endpoints ─────────────────────────────────────

    @Test
    @DisplayName("POST /api/chat/init with valid mode returns 200 INITIALIZED")
    void initChat_validMode_returns200() throws Exception {
        Mockito.when(chatDemoService.getCurrentMode()).thenReturn("HYBRID");
        mockMvc.perform(post("/api/chat/init").param("mode", "HYBRID"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("INITIALIZED")));
    }

    @Test
    @DisplayName("POST /api/chat/init with invalid mode returns 400")
    void initChat_invalidMode_returns400() throws Exception {
        mockMvc.perform(post("/api/chat/init").param("mode", "QUANTUM_BROKEN"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Bad Request")));
    }

    @Test
    @DisplayName("POST /api/chat/send with message returns delivery result")
    void sendChat_validMessage_returnsDelivery() throws Exception {
        ChatDemoService.ChatSendResult fakeResult = new ChatDemoService.ChatSendResult(
                "Alice", "Hello Bob!", 0L, "3a4b5c6d", "[Encrypted Record seq=0]: 3a4b5c6d...", "ACCEPTED", "HYBRID"
        );
        Mockito.when(chatDemoService.sendMessage("Hello Bob!")).thenReturn(fakeResult);

        mockMvc.perform(post("/api/chat/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"message\": \"Hello Bob!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sender", is("Alice")))
                .andExpect(jsonPath("$.message", is("Hello Bob!")))
                .andExpect(jsonPath("$.sequenceNumber", is(0)));
    }

    @Test
    @DisplayName("POST /api/chat/send with empty message returns 400")
    void sendChat_emptyMessage_returns400() throws Exception {
        mockMvc.perform(post("/api/chat/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"message\": \"   \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("Bad Request")));
    }

    @Test
    @DisplayName("POST /api/chat/attacker/replay returns attacker action result")
    void attackerReplay_returnsResult() throws Exception {
        ChatDemoService.AttackerActionResult fakeResult = new ChatDemoService.AttackerActionResult(
                "REPLAY", "BLOCKED", "Replay of record seq=0 BLOCKED", "DET-REPLAY-1", "HYBRID"
        );
        Mockito.when(chatDemoService.replayLastMessage()).thenReturn(fakeResult);

        mockMvc.perform(post("/api/chat/attacker/replay"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.action", is("REPLAY")))
                .andExpect(jsonPath("$.outcome", is("BLOCKED")));
    }

    @Test
    @DisplayName("POST /api/chat/attacker/flip-bit returns attacker action result")
    void attackerFlipBit_returnsResult() throws Exception {
        ChatDemoService.AttackerActionResult fakeResult = new ChatDemoService.AttackerActionResult(
                "TAMPER", "BLOCKED", "Tampering BLOCKED by GCM tag check", "DET-TAMPER-1", "HYBRID"
        );
        Mockito.when(chatDemoService.flipBit()).thenReturn(fakeResult);

        mockMvc.perform(post("/api/chat/attacker/flip-bit"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.action", is("TAMPER")))
                .andExpect(jsonPath("$.outcome", is("BLOCKED")));
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private List<SecurityMatrixResult> buildFakeMatrix(int count) {
        String[] attacks = {"Downgrade", "MITM", "Replay", "Nonce Reuse", "Tampering"};
        String[] modes   = {"CLASSICAL-VULNERABLE", "CLASSICAL-HARDENED", "HYBRID"};
        List<SecurityMatrixResult> list = new java.util.ArrayList<>();
        int idx = 0;
        outer:
        for (String atk : attacks) {
            for (String mode : modes) {
                if (idx++ >= count) break outer;
                list.add(new SecurityMatrixResult(atk, mode, true, false, "DET-SAMPLE-" + idx, "Sample evidence"));
            }
        }
        return list;
    }

    private List<DetectionEvent> buildFakeEvents(int count) {
        List<DetectionEvent> list = new java.util.ArrayList<>();
        for (int i = 0; i < count; i++) {
            list.add(DetectionEvent.create(
                    DetectionEvent.AttackType.REPLAY,
                    DetectionEvent.Severity.MEDIUM,
                    "TestComponent",
                    "HYBRID",
                    DetectionEvent.Action.BLOCKED,
                    "Test detection event #" + i
            ));
        }
        return list;
    }

    private ScanReport buildFakeScanReport(String grade, int score, int total) {
        ScanSummary summary = new ScanSummary(total, Map.of("CRITICAL", 0, "HIGH", 0), score, grade, 1.0 - score / 100.0);
        return new ScanReport("test-" + grade, "test-target", "2026-11-23T00:00:00Z", summary, Collections.emptyList());
    }
}
