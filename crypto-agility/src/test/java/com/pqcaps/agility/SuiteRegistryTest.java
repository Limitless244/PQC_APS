package com.pqcaps.agility;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SuiteRegistry}.
 */
class SuiteRegistryTest {

    @Test
    void defaultRegistryAllowsAllSuites() {
        SuiteRegistry registry = new SuiteRegistry(false);

        assertThat(registry.resolveSuite("CLASSICAL")).isNotNull();
        assertThat(registry.resolveSuite("HYBRID")).isNotNull();
        assertThat(registry.resolveSuite("PQ_ONLY")).isNotNull();
        assertThat(registry.resolveSuite(AlgorithmSuite.HYBRID).getKemAlgorithm()).isEqualTo("ML-KEM-768");
    }

    @Test
    void rejectClassicalPolicyBlocksClassicalSuite() {
        SuiteRegistry registry = new SuiteRegistry(true);

        assertThatThrownBy(() -> registry.resolveSuite("CLASSICAL"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("rejected by security policy");

        assertThatThrownBy(() -> registry.resolveSuite(AlgorithmSuite.CLASSICAL))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("rejected by security policy");

        // HYBRID and PQ_ONLY are still accepted
        assertThat(registry.resolveSuite("HYBRID")).isNotNull();
        assertThat(registry.resolveSuite("PQ_ONLY")).isNotNull();
    }

    @Test
    void unknownSuiteThrowsIllegalArgumentException() {
        SuiteRegistry registry = new SuiteRegistry(false);

        assertThatThrownBy(() -> registry.resolveSuite("DES_EDE3_CBC"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown algorithm suite");
    }
}
