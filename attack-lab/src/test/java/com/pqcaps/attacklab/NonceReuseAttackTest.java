package com.pqcaps.attacklab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for ATTACK 4: AES-GCM Nonce Reuse Keystream Leak (VULN-3).
 *
 * <p>Phase 2 Expectation: Attack SUCCEEDS in recovering the secret plaintext via keystream XOR cancellation.
 */
class NonceReuseAttackTest {

    @Test
    @DisplayName("Phase 2: Nonce reuse allows complete plaintext recovery via C1^C2 = P1^P2 (VULN-3)")
    void nonceReuseAttack_succeedsInRecoveringPlaintext() {
        AttackResult result = NonceReuseAttack.execute();

        assertThat(result.vulnerabilityId()).isEqualTo("VULN-3");
        assertThat(result.success())
                .as("GCM Nonce reuse MUST allow plaintext recovery (VULN-3 active)")
                .isTrue();
        assertThat(result.evidence())
                .contains("C1^C2 == P1^P2")
                .contains("TRANSFER $950 TO EVE");
    }
}
