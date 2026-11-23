package com.pqcaps.attacklab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for ATTACK 3: Transaction Record Replay (VULN-2).
 *
 * <p>Phase 2 Expectation: Attack SUCCEEDS when server skips sequence number checks.
 * When sequence check is enabled, the replay fails.
 */
class ReplayAttackTest {

    @Test
    @DisplayName("Phase 2: Replay attack succeeds when sequence check is disabled (VULN-2)")
    void replayAttack_succeedsWhenSequenceCheckDisabled() {
        AttackResult result = ReplayAttack.execute(true); // skipSequenceCheck = true

        assertThat(result.vulnerabilityId()).isEqualTo("VULN-2");
        assertThat(result.success())
                .as("Replay attack MUST succeed when server skips sequence number validation (VULN-2 active)")
                .isTrue();
        assertThat(result.evidence()).contains("processed 2 times");
    }

    @Test
    @DisplayName("Phase 2 baseline check: Replay attack fails when sequence check is enabled")
    void replayAttack_failsWhenSequenceCheckEnabled() {
        AttackResult result = ReplayAttack.execute(false); // skipSequenceCheck = false

        assertThat(result.success())
                .as("Replay attack MUST fail when server validates sequence numbers")
                .isFalse();
        assertThat(result.evidence()).contains("rejected");
    }
}
