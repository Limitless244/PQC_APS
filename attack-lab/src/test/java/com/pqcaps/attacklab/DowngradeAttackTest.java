package com.pqcaps.attacklab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for ATTACK 1: Cipher Suite Downgrade (VULN-1).
 *
 * <p>Phase 2 Expectation: Attack SUCCEEDS against the vulnerable baseline.
 * Phase 4 note: When testing against hardened config, this expectation flips to failure.
 */
class DowngradeAttackTest {

    @Test
    @DisplayName("Phase 2: Downgrade attack succeeds against vulnerable handshake (VULN-1)")
    void downgradeAttack_succeedsAgainstVulnerableConfig() {
        AttackResult result = DowngradeAttack.execute(true);

        assertThat(result.vulnerabilityId()).isEqualTo("VULN-1");
        assertThat(result.success())
                .as("Downgrade attack MUST succeed against vulnerable configuration (VULN-1 active)")
                .isTrue();
        assertThat(result.evidence())
                .contains("BEFORE: [HYBRID, CLASSICAL]")
                .contains("AFTER: [CLASSICAL]")
                .contains("Handshake accepted: true");
    }

    @Test
    @DisplayName("Phase 2 baseline check: Downgrade attack is blocked when suite list is signed")
    void downgradeAttack_failsAgainstSafeConfig() {
        AttackResult result = DowngradeAttack.execute(false);

        assertThat(result.success())
                .as("Downgrade attack MUST fail when suite list is covered by the signature")
                .isFalse();
        assertThat(result.evidence()).contains("rejected");
    }
}
