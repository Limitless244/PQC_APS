package com.pqcaps.dashboard.controller;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attacklab.SecurityMatrixResult;
import com.pqcaps.dashboard.benchmark.BenchmarkReport;
import com.pqcaps.dashboard.service.DashboardDataService;
import com.pqcaps.scanner.ScanReport;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://127.0.0.1:8080")
public class ApiController {

    private final DashboardDataService dataService;

    public ApiController(DashboardDataService dataService) {
        this.dataService = dataService;
    }

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
}
