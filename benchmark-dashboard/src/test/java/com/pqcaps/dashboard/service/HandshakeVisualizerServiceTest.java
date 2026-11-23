package com.pqcaps.dashboard.service;

import com.pqcaps.common.HandshakeStepEvent;
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
        assertThat(result.totalWireBytes()).isEqualTo(6098); // 1356 + 4488 + 127 + 127
        assertThat(result.steps()).isNotEmpty();

        List<String> stepNames = result.steps().stream().map(HandshakeStepEvent::stepName).toList();
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
        assertThat(result.totalWireBytes()).isEqualTo(501); // 111 + 390

        List<String> stepNames = result.steps().stream().map(HandshakeStepEvent::stepName).toList();
        assertThat(stepNames).containsSubsequence(
                "ClientHello",
                "ServerHello",
                "SignatureCheck",
                "ChannelEstablished"
        );
    }

    @Test
    @DisplayName("Invalid suite throws IllegalArgumentException")
    void invalidSuiteThrowsException() {
        assertThatThrownBy(() -> service.executeHandshake("INVALID_SUITE"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid suite");
    }
}
