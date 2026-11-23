package com.pqcaps.dashboard.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Simulator Service Verification")
class SimulatorServiceTest {

    private final SimulatorService service = new SimulatorService();

    @Test
    @DisplayName("Running Downgrade on HYBRID returns blocked outcome with explanation and steps")
    void downgradeHybridBlocked() {
        SimulatorService.AttackSimulationResponse res = service.runSimulation("Downgrade", "HYBRID");

        assertThat(res.attack()).isEqualTo("Downgrade");
        assertThat(res.mode()).isEqualTo("HYBRID");
        assertThat(res.attackSucceeded()).isFalse();
        assertThat(res.defenceTriggered()).isTrue();
        assertThat(res.explanation()).isNotBlank();
        assertThat(res.attackerSteps()).isNotEmpty();
    }

    @Test
    @DisplayName("Running Replay on CLASSICAL-VULNERABLE returns succeeded outcome")
    void replayVulnerableSucceeded() {
        SimulatorService.AttackSimulationResponse res = service.runSimulation("Replay", "CLASSICAL-VULNERABLE");

        assertThat(res.attack()).isEqualTo("Replay");
        assertThat(res.mode()).isEqualTo("CLASSICAL-VULNERABLE");
        assertThat(res.attackSucceeded()).isTrue();
    }

    @Test
    @DisplayName("Invalid attack name throws IllegalArgumentException")
    void invalidAttackThrows() {
        assertThatThrownBy(() -> service.runSimulation("BUFFER_OVERFLOW", "HYBRID"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid attack name");
    }

    @Test
    @DisplayName("Invalid mode throws IllegalArgumentException")
    void invalidModeThrows() {
        assertThatThrownBy(() -> service.runSimulation("Downgrade", "NON_EXISTENT_MODE"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid mode");
    }
}
