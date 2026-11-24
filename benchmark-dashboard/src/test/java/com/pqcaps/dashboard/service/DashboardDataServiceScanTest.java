package com.pqcaps.dashboard.service;

import com.pqcaps.scanner.ScanReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Dashboard Data Service Scanner Resolution Tests")
public class DashboardDataServiceScanTest {

    @ParameterizedTest
    @ValueSource(strings = {"vulnerable", "migrated", "self", "self-production", "self-tests"})
    @DisplayName("loadScanReport returns valid report with score, grade, and points")
    void loadScanReport_validTarget_returnsValidReport(String target) {
        DashboardDataService service = new DashboardDataService();
        ScanReport report = service.loadScanReport(target);
        assertNotNull(report, "Scan report should not be null for " + target);
        assertNotNull(report.summary(), "Summary should not be null for " + target);
        assertTrue(report.summary().overallScore() >= 0 && report.summary().overallScore() <= 100,
                "Score out of range [0, 100]: " + report.summary().overallScore());
        assertNotNull(report.summary().grade(), "Grade should not be null for " + target);
        assertTrue(report.summary().riskPoints() >= 0, "Risk points should be >= 0");
    }

    @ParameterizedTest
    @ValueSource(strings = {"vulnerable", "migrated", "self", "self-production", "self-tests"})
    @DisplayName("runScan in-process returns valid report with score, grade, and points")
    void runScan_validTarget_executesInProcess(String target) {
        DashboardDataService service = new DashboardDataService();
        ScanReport report = service.runScan(target);
        assertNotNull(report, "Scan report should not be null for " + target);
        assertNotNull(report.summary(), "Summary should not be null for " + target);
        assertTrue(report.summary().overallScore() >= 0 && report.summary().overallScore() <= 100);
        assertNotNull(report.summary().grade());
        assertTrue(report.summary().riskPoints() >= 0);
    }
}
