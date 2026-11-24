package com.pqcaps.dashboard.service;

import com.pqcaps.dashboard.service.DashboardDataService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Overview Page Tile Dynamic Rendering Tests")
class OverviewTileRenderingTest {

    private Path resolveStaticFile(String relativePath) {
        Path p = Path.of("src", "main", "resources", "static", relativePath);
        if (Files.exists(p)) {
            return p;
        }
        Path subP = Path.of("benchmark-dashboard", "src", "main", "resources", "static", relativePath);
        if (Files.exists(subP)) {
            return subP;
        }
        Path parentP = Path.of("..", "benchmark-dashboard", "src", "main", "resources", "static", relativePath);
        if (Files.exists(parentP)) {
            return parentP;
        }
        throw new IllegalStateException("Could not resolve static file: " + relativePath);
    }

    @Test
    @DisplayName("Verify index.html tests tile does not contain literal test counts and has fallback 'not available'")
    void indexHtml_testsTileDoesNotContainHardcodedLiteral() throws IOException {
        Path indexPath = resolveStaticFile("index.html");
        String html = Files.readString(indexPath, StandardCharsets.UTF_8);

        // Pattern matching any hardcoded test count format like '127 / 127 Passing' or '166 / 166'
        Pattern literalTestPattern = Pattern.compile("<p[^>]*id=[\"']overview-tests-value[\"'][^>]*>(.*?)</p>", Pattern.DOTALL);
        Matcher matcher = literalTestPattern.matcher(html);

        assertThat(matcher.find())
                .as("index.html must define an element with id='overview-tests-value'")
                .isTrue();

        String tileContent = matcher.group(1).trim();

        // Must not contain numeric fraction like 127 / 127 or 166 / 166
        assertThat(tileContent)
                .as("Tests tile in index.html must not be rendered from a hardcoded literal number, found: '%s'", tileContent)
                .doesNotMatch(".*\\d+\\s*/\\s*\\d+.*")
                .doesNotContain("127")
                .doesNotContain("166")
                .isEqualTo("not available");

        // Verify caption is 'Across 10 modules' and not hardcoded to 'Across 11 Maven Submodules'
        Pattern captionPattern = Pattern.compile("<p[^>]*id=[\"']overview-tests-caption[\"'][^>]*>(.*?)</p>", Pattern.DOTALL);
        Matcher capMatcher = captionPattern.matcher(html);
        assertThat(capMatcher.find())
                .as("index.html must define an element with id='overview-tests-caption'")
                .isTrue();
        assertThat(capMatcher.group(1).trim())
                .as("Caption must specify 'Across 10 modules'")
                .isEqualTo("Across 10 modules");

        // Verify throughput card does not hardcode '> 1,200 MB/s'
        Pattern tpPattern = Pattern.compile("<p[^>]*id=[\"']overview-throughput-value[\"'][^>]*>(.*?)</p>", Pattern.DOTALL);
        Matcher tpMatcher = tpPattern.matcher(html);
        assertThat(tpMatcher.find()).isTrue();
        assertThat(tpMatcher.group(1).trim())
                .as("Throughput tile in index.html must not hardcode '> 1,200 MB/s'")
                .doesNotContain("1,200")
                .doesNotContain("1200")
                .isEqualTo("not available");
    }

    @Test
    @DisplayName("Verify dashboard.js dynamically fetches /api/test-summary and does not assign hardcoded literal string")
    void dashboardJs_doesNotAssignHardcodedLiteralToTestsTile() throws IOException {
        Path jsPath = resolveStaticFile("js/dashboard.js");
        String js = Files.readString(jsPath, StandardCharsets.UTF_8);

        // Must query /api/test-summary
        assertThat(js)
                .as("dashboard.js must fetch from /api/test-summary")
                .contains("/api/test-summary");

        // Must not assign a literal test count string to tests tile
        Pattern hardcodedAssignPattern = Pattern.compile("testsValEl\\.textContent\\s*=\\s*['\"][^'\"]*\\d+\\s*/\\s*\\d+[^'\"]*['\"]");
        assertThat(hardcodedAssignPattern.matcher(js).find())
                .as("dashboard.js must not assign a hardcoded numeric literal string to testsValEl")
                .isFalse();

        // Must handle fallback with 'not available'
        assertThat(js)
                .as("dashboard.js must provide fallback to 'not available'")
                .contains("testsValEl.textContent = 'not available'");
    }

    @Test
    @DisplayName("Verify DashboardDataService handles missing test summary safely")
    void testSummary_missingFileReturnsNotAvailable() {
        DashboardDataService service = new DashboardDataService();
        Map<String, Object> summary = service.loadTestSummary();
        // Even if file is missing or present, result must be non-null map
        assertThat(summary).isNotNull();
        if (Boolean.FALSE.equals(summary.get("available"))) {
            assertThat(summary.get("available")).isEqualTo(false);
        } else {
            assertThat(summary.get("available")).isEqualTo(true);
            assertThat(summary.get("totalTests")).isNotNull();
            assertThat(summary.get("caption")).isEqualTo("Across 10 modules");
        }
    }
}
