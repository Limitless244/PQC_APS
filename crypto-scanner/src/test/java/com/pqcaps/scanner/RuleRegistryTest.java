package com.pqcaps.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Rule Registry Tests")
class RuleRegistryTest {

    @Test
    @DisplayName("Verify rules.yaml loads properly with all required rules")
    void testRulesLoaded() {
        RuleRegistry registry = RuleRegistry.getInstance();
        Collection<Rule> rules = registry.getAllRules();

        assertThat(rules).isNotEmpty();

        // Check key rules are present
        assertThat(registry.getRule("RULE-RSA")).isNotNull();
        assertThat(registry.getRule("RULE-RSA-WEAK")).isNotNull();
        assertThat(registry.getRule("RULE-ECC")).isNotNull();
        assertThat(registry.getRule("RULE-DH-DSA")).isNotNull();
        assertThat(registry.getRule("RULE-MD5")).isNotNull();
        assertThat(registry.getRule("RULE-SHA1")).isNotNull();
        assertThat(registry.getRule("RULE-DES-3DES")).isNotNull();
        assertThat(registry.getRule("RULE-RC4-BLOWFISH")).isNotNull();
        assertThat(registry.getRule("RULE-AES-ECB")).isNotNull();
        assertThat(registry.getRule("RULE-AES128")).isNotNull();
        assertThat(registry.getRule("RULE-HARDCODED-SECRET")).isNotNull();
        assertThat(registry.getRule("RULE-WEAK-RNG")).isNotNull();
        assertThat(registry.getRule("RULE-STATIC-IV")).isNotNull();
        assertThat(registry.getRule("RULE-TLS-LEGACY")).isNotNull();
        assertThat(registry.getRule("RULE-TLS-CERT-QV")).isNotNull();
        assertThat(registry.getRule("RULE-PQC-READY")).isNotNull();
    }
}
