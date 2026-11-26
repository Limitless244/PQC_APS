package com.pqcaps.dashboard.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Handshake Visualizer Service Verification")
class HandshakeVisualizerServiceTest {

    private final HandshakeVisualizerService service = new HandshakeVisualizerService();

    @Test
    @DisplayName("executeHandshake in HYBRID mode produces ordered steps, NIST wire bytes, and SECURE outcome")
    void hybridStreamEmitsOrderedSteps() {
        HandshakeVisualizerService.HandshakeVisualizerResult result = service.executeHandshake("HYBRID");

        assertThat(result.suite()).isEqualTo("HYBRID");
        assertThat(result.outcome()).isEqualTo("SECURE");
        assertThat(result.totalWireBytes()).isEqualTo(6433); // WireSizeComparisonTest serialized total (1504 + 4675 + 127 + 127)
        assertThat(result.payloadBytes()).isEqualTo(6098);   // Payload before framing (1356 + 4488 + 127 + 127)
        assertThat(result.steps()).isNotEmpty();

        List<String> stepNames = result.steps().stream().map(s -> s.stepName()).toList();
        assertThat(stepNames).containsSubsequence(
                "ClientHello",
                "ServerHello",
                "SignatureCheck",
                "ClientFinished",
                "ServerFinished",
                "ChannelEstablished"
        );
    }

    @Test
    @DisplayName("executeHandshake in CLASSICAL mode produces classical steps, wire bytes, and SECURE outcome")
    void classicalStreamEmitsOrderedSteps() {
        HandshakeVisualizerService.HandshakeVisualizerResult result = service.executeHandshake("CLASSICAL");

        assertThat(result.suite()).isEqualTo("CLASSICAL");
        assertThat(result.outcome()).isEqualTo("SECURE");
        assertThat(result.totalWireBytes()).isEqualTo(820);  // WireSizeComparisonTest serialized total (292 + 528)
        assertThat(result.payloadBytes()).isEqualTo(501);    // Payload before framing (111 + 390)

        List<String> stepNames = result.steps().stream().map(s -> s.stepName()).toList();
        assertThat(stepNames).containsSubsequence(
                "ClientHello",
                "ServerHello",
                "SignatureCheck",
                "ChannelEstablished"
        );
    }

    @Test
    @DisplayName("Visualizer HYBRID and CLASSICAL totals equal WireSizeComparisonTest values")
    void visualizerTotalsMatchWireSizeComparisonTest() {
        HandshakeVisualizerService.HandshakeVisualizerResult hybridRes = service.executeHandshake("HYBRID");
        assertThat(hybridRes.totalWireBytes()).isEqualTo(6433);
        assertThat(hybridRes.payloadBytes()).isEqualTo(6098);

        HandshakeVisualizerService.HandshakeVisualizerResult classicalRes = service.executeHandshake("CLASSICAL");
        assertThat(classicalRes.totalWireBytes()).isEqualTo(820);
        assertThat(classicalRes.payloadBytes()).isEqualTo(501);
    }

    @Test
    @DisplayName("executeHandshakeX5 returns 5 runs and computes valid mean and min of last 4 runs")
    void executeHandshakeX5ReturnsValidStatistics() {
        HandshakeVisualizerService.HandshakeX5Result res = service.executeHandshakeX5("HYBRID");

        assertThat(res.suite()).isEqualTo("HYBRID");
        assertThat(res.runsMillis()).hasSize(5);
        assertThat(res.coldStartMillis()).isEqualTo(res.runsMillis().get(0));
        assertThat(res.meanLast4Millis()).isPositive();
        assertThat(res.minLast4Millis()).isPositive().isLessThanOrEqualTo(res.meanLast4Millis());
        assertThat(res.totalWireBytes()).isEqualTo(6433);
        assertThat(res.payloadBytes()).isEqualTo(6098);
    }

    @Test
    @DisplayName("Invalid suite throws IllegalArgumentException")
    void invalidSuiteThrowsException() {
        assertThatThrownBy(() -> service.executeHandshake("INVALID_SUITE"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid suite");
    }
}
