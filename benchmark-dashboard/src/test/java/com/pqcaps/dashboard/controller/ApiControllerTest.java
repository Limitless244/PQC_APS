package com.pqcaps.dashboard.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attacklab.SecurityMatrixResult;
import com.pqcaps.dashboard.benchmark.BenchmarkReport;
import com.pqcaps.dashboard.benchmark.BenchmarkRunner;
import com.pqcaps.dashboard.service.DashboardDataService;
import com.pqcaps.scanner.ScanReport;
import com.pqcaps.scanner.ScanSummary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Controller-layer tests for ApiController.
 * Uses @WebMvcTest so Spring context is minimal and fast.
 * DashboardDataService is mocked to avoid I/O in unit tests.
 */
@WebMvcTest(controllers = {ApiController.class, GlobalExceptionHandler.class})
@DisplayName("API Controller Tests")
class ApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DashboardDataService dataService;

    // ── GET /api/attacks ──────────────────────────────────────────────────

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
    @DisplayName("GET /api/attacks returns empty list when no data")
    void getAttacks_returnsEmptyList() throws Exception {
        Mockito.when(dataService.loadAttacks()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/attacks").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    // ── GET /api/events ──────────────────────────────────────────────────

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
    @DisplayName("GET /api/events uses default limit when no param given")
    void getEvents_defaultLimit() throws Exception {
        Mockito.when(dataService.loadEvents(50)).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/events").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    // ── GET /api/scan/{target} ───────────────────────────────────────────

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

    @Test
    @DisplayName("GET /api/scan/migrated returns report with grade A")
    void getScan_migrated_returnsGradeA() throws Exception {
        ScanReport report = buildFakeScanReport("A", 0, 0);
        Mockito.when(dataService.loadScanReport("migrated")).thenReturn(report);

        mockMvc.perform(get("/api/scan/migrated").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.grade", is("A")))
                .andExpect(jsonPath("$.summary.overallScore", is(0)));
    }

    @Test
    @DisplayName("GET /api/scan/self returns report with totalFindings")
    void getScan_self_returnsReport() throws Exception {
        ScanReport report = buildFakeScanReport("A-", 12, 3);
        Mockito.when(dataService.loadScanReport("self")).thenReturn(report);

        mockMvc.perform(get("/api/scan/self").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.totalFindings", is(3)));
    }

    @Test
    @DisplayName("GET /api/scan/unknown returns 400 JSON (no stack trace)")
    void getScan_unknownTarget_returns400Json() throws Exception {
        Mockito.when(dataService.loadScanReport("unknown"))
                .thenThrow(new IllegalArgumentException("Invalid scan target 'unknown'. Allowed targets: vulnerable, migrated, self"));

        mockMvc.perform(get("/api/scan/unknown").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", containsString("unknown")))
                .andExpect(jsonPath("$.status", is(400)))
                // Verify no Java stack trace leaks into the response
                .andExpect(jsonPath("$", not(hasKey("trace"))))
                .andExpect(jsonPath("$", not(hasKey("exception"))));
    }

    @Test
    @DisplayName("GET /api/scan/missing returns 404 JSON when file not found")
    void getScan_missingFile_returns404Json() throws Exception {
        Mockito.when(dataService.loadScanReport("vulnerable"))
                .thenThrow(new NoSuchElementException("Scan report not found for target: vulnerable"));

        mockMvc.perform(get("/api/scan/vulnerable").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error", is("Not Found")))
                .andExpect(jsonPath("$.status", is(404)))
                .andExpect(jsonPath("$", not(hasKey("trace"))));
    }

    // ── GET /api/benchmarks ──────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/benchmarks returns report with machine info")
    void getBenchmarks_returnsMachineInfo() throws Exception {
        BenchmarkReport report = BenchmarkRunner.run(true);
        Mockito.when(dataService.loadBenchmarks()).thenReturn(report);

        mockMvc.perform(get("/api/benchmarks").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.machine").exists())
                .andExpect(jsonPath("$.machine.jdkVersion").isNotEmpty())
                .andExpect(jsonPath("$.sizes").isArray())
                .andExpect(jsonPath("$.latency").isArray())
                .andExpect(jsonPath("$.throughput").isArray());
    }

    // ── POST /api/demo/run-attacks ───────────────────────────────────────

    @Test
    @DisplayName("POST /api/demo/run-attacks returns 15 results")
    void runAttacks_returns15Rows() throws Exception {
        List<SecurityMatrixResult> matrix = buildFakeMatrix(15);
        Mockito.when(dataService.runAttacks()).thenReturn(matrix);

        mockMvc.perform(post("/api/demo/run-attacks").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(15)));
    }

    // ── GET /api/events/stream — SSE endpoint ───────────────────────────

    @Test
    @DisplayName("GET /api/events/stream returns text/event-stream content type")
    void getEventsStream_returnsSseContentType() throws Exception {
        // SseEmitter setup: service returns a live emitter
        Mockito.when(dataService.registerEmitter())
                .thenAnswer(inv -> {
                    var emitter = new org.springframework.web.servlet.mvc.method.annotation.SseEmitter(100L);
                    emitter.complete(); // complete immediately so request finishes
                    return emitter;
                });

        mockMvc.perform(get("/api/events/stream"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM));
    }

    // ── Error handler: 500 for unexpected exceptions ─────────────────────

    @Test
    @DisplayName("Unexpected exception returns 500 JSON without stack trace")
    void unexpectedException_returns500WithoutStackTrace() throws Exception {
        Mockito.when(dataService.loadAttacks())
                .thenThrow(new RuntimeException("simulated unexpected failure"));

        mockMvc.perform(get("/api/attacks").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error", is("Internal Server Error")))
                .andExpect(jsonPath("$.status", is(500)))
                // Message must NOT reveal implementation details
                .andExpect(jsonPath("$.message", containsString("unexpected")))
                .andExpect(jsonPath("$", not(hasKey("trace"))));
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private List<SecurityMatrixResult> buildFakeMatrix(int count) {
        String[] attacks = {"Downgrade", "MITM", "Replay", "Nonce Reuse", "Tampering"};
        String[] modes   = {"CLASSICAL-VULNERABLE", "CLASSICAL-HARDENED", "HYBRID"};
        java.util.List<SecurityMatrixResult> list = new java.util.ArrayList<>();
        int idx = 0;
        outer:
        for (String atk : attacks) {
            for (String mode : modes) {
                if (idx++ >= count) break outer;
                list.add(new SecurityMatrixResult(atk, mode, true, "DET-SAMPLE-" + idx, "Sample evidence for test"));
            }
        }
        return list;
    }

    private List<DetectionEvent> buildFakeEvents(int count) {
        java.util.List<DetectionEvent> list = new java.util.ArrayList<>();
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
