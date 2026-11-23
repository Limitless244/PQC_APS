package com.pqcaps.attacklab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for ATTACK 2: Man-In-The-Middle Eavesdropping (VULN-4).
 *
 * <p>Phase 2 Expectation: Attack SUCCEEDS when client skips key pinning.
 * When key pinning is enabled, the attack fails.
 */
class MitmAttackTest {

    @Test
    @DisplayName("Phase 2: MITM attack succeeds when client skips server key pinning (VULN-4)")
    void mitmAttack_succeedsWhenKeyPinningSkipped() {
        AttackResult result = MitmAttack.execute(true); // skipKeyPinning = true

        assertThat(result.vulnerabilityId()).isEqualTo("VULN-4");
        assertThat(result.success())
                .as("MITM attack MUST succeed when client skips key pinning (VULN-4 active)")
                .isTrue();
        assertThat(result.evidence()).contains("TRANSFER $50,000");
    }

    @Test
    @DisplayName("Phase 2 baseline check: MITM attack fails when client verifies pinned server key")
    void mitmAttack_failsWhenKeyPinningEnabled() {
        AttackResult result = MitmAttack.execute(false); // skipKeyPinning = false

        assertThat(result.success())
                .as("MITM attack MUST fail when client verifies server identity signature")
                .isFalse();
        assertThat(result.evidence()).contains("MITM blocked");
    }
}
