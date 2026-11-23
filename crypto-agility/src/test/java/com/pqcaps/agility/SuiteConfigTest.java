package com.pqcaps.agility;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Phase 0 smoke tests for the crypto-agility module.
 *
 * <p>These tests confirm the module compiles correctly and that the
 * SuiteConfig defaults are sane. Full algorithm-correctness tests
 * arrive in Phase 3.
 *
 * <p><b>Trace (how to follow along)</b>:
 * <pre>
 * Input : AlgorithmSuite.HYBRID
 * Step 1: SuiteConfig.forSuite(HYBRID) is called
 * Step 2: switch selects the HYBRID branch
 * Step 3: returns a SuiteConfig with kemAlgorithm = "ML-KEM-768"
 * Output: kemAlgorithm == "ML-KEM-768"  ✓
 * </pre>
 */
class SuiteConfigTest {

    @Test
    void hybridSuite_hasCorrectAlgorithms() {
        SuiteConfig cfg = SuiteConfig.forSuite(AlgorithmSuite.HYBRID);

        assertThat(cfg.getSuite()).isEqualTo(AlgorithmSuite.HYBRID);
        assertThat(cfg.getKemAlgorithm()).isEqualTo("ML-KEM-768");
        assertThat(cfg.getClassicalKemAlgorithm()).isEqualTo("XDH");
        assertThat(cfg.getSignatureAlgorithm()).isEqualTo("ML-DSA-65");
        assertThat(cfg.getSymmetricAlgorithm()).isEqualTo("AES/GCM/NoPadding");
        assertThat(cfg.getSymmetricKeyBits()).isEqualTo(256);
        assertThat(cfg.getKdfAlgorithm()).isEqualTo("HkdfSHA256");
    }

    @Test
    void classicalSuite_hasCorrectAlgorithms() {
        SuiteConfig cfg = SuiteConfig.forSuite(AlgorithmSuite.CLASSICAL);

        assertThat(cfg.getSuite()).isEqualTo(AlgorithmSuite.CLASSICAL);
        assertThat(cfg.getKemAlgorithm()).isEqualTo("XDH");
        assertThat(cfg.getSignatureAlgorithm()).isEqualTo("SHA256withECDSA");
        assertThat(cfg.getSymmetricKeyBits()).isEqualTo(256);
    }

    @Test
    void pqOnlySuite_hasNoClassicalKem() {
        SuiteConfig cfg = SuiteConfig.forSuite(AlgorithmSuite.PQ_ONLY);

        assertThat(cfg.getSuite()).isEqualTo(AlgorithmSuite.PQ_ONLY);
        assertThat(cfg.getKemAlgorithm()).isEqualTo("ML-KEM-768");
        // PQ_ONLY has no classical KEM component — must be null
        assertThat(cfg.getClassicalKemAlgorithm()).isNull();
    }

    @Test
    void allSuites_useAes256Gcm() {
        for (AlgorithmSuite suite : AlgorithmSuite.values()) {
            SuiteConfig cfg = SuiteConfig.forSuite(suite);
            assertThat(cfg.getSymmetricAlgorithm())
                .as("Suite %s must use AES-256-GCM", suite)
                .isEqualTo("AES/GCM/NoPadding");
            assertThat(cfg.getSymmetricKeyBits())
                .as("Suite %s must use 256-bit keys", suite)
                .isEqualTo(256);
        }
    }
}
