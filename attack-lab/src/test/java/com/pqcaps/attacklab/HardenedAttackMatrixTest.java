package com.pqcaps.attacklab;

import com.pqcaps.common.HandshakeConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Phase 4 Security Matrix Verification")
class HardenedAttackMatrixTest {

    @Test
    @DisplayName("Verify full 5-attack x 3-mode security matrix with real code execution")
    void testSecurityMatrix() throws Exception {
        SecurityMatrixRunner runner = new SecurityMatrixRunner();
        List<SecurityMatrixResult> matrix = runner.runFullMatrix();

        SecurityMatrixRunner.printMatrixTable(matrix);

        // Save to data/attack-results.json for inspection and Phase 6 dashboard
        java.nio.file.Path jsonPath = com.pqcaps.common.DataPaths.resolve("attack-results.json");
        File jsonFile = jsonPath.toFile();
        SecurityMatrixResult.saveToJson(jsonFile, matrix);
        assertThat(jsonFile).exists();

        // Step 0 check: Assert attack-results.json has exactly 15 rows (5 attacks x 3 modes)
        assertThat(matrix).hasSize(15);
        List<SecurityMatrixResult> loaded = SecurityMatrixResult.loadFromJson(jsonFile);
        assertThat(loaded).hasSize(15);

        // Verify Tampering/CLASSICAL-VULNERABLE status is UNDETECTED
        // Verify Tampering/CLASSICAL-VULNERABLE status is UNDETECTED with attackSucceeded=false and detected=false
        SecurityMatrixResult tamperVuln = findResult(matrix, "Tampering", "CLASSICAL-VULNERABLE");
        assertThat(tamperVuln).isNotNull();
        assertThat(tamperVuln.status()).isEqualTo("UNDETECTED");
        assertThat(tamperVuln.attackSucceeded()).isFalse();
        assertThat(tamperVuln.detected()).isFalse();

        SecurityMatrixResult loadedTamperVuln = findResult(loaded, "Tampering", "CLASSICAL-VULNERABLE");
        assertThat(loadedTamperVuln).isNotNull();
        assertThat(loadedTamperVuln.status()).isEqualTo("UNDETECTED");
        assertThat(loadedTamperVuln.attackSucceeded()).isFalse();
        assertThat(loadedTamperVuln.detected()).isFalse();

        List<String> attacks = List.of("Downgrade", "MITM", "Replay", "Nonce Reuse", "Tampering");

        for (String attack : attacks) {
            // 1. CLASSICAL-VULNERABLE: Attack must SUCCEED (or UNDETECTED for Tampering), defence NOT triggered
            SecurityMatrixResult vuln = findResult(matrix, attack, "CLASSICAL-VULNERABLE");
            assertThat(vuln).isNotNull();
            if ("Tampering".equals(attack)) {
                assertThat(vuln.attackSucceeded())
                        .as("Tampering in CLASSICAL-VULNERABLE does not succeed (decryption fails)")
                        .isFalse();
                assertThat(vuln.detected())
                        .as("Tampering in CLASSICAL-VULNERABLE is undetected")
                        .isFalse();
                assertThat(vuln.status())
                        .isEqualTo("UNDETECTED");
            } else {
                assertThat(vuln.attackSucceeded())
                        .as("Attack " + attack + " should succeed in CLASSICAL-VULNERABLE mode")
                        .isTrue();
            }
            assertThat(vuln.defenceTriggered())
                    .as("Defence should NOT be triggered in CLASSICAL-VULNERABLE mode")
                    .isFalse();

            // 2. CLASSICAL-HARDENED: Attack must be BLOCKED, defence TRIGGERED, eventId recorded
            SecurityMatrixResult hardened = findResult(matrix, attack, "CLASSICAL-HARDENED");
            assertThat(hardened).isNotNull();
            assertThat(hardened.attackSucceeded())
                    .as("Attack " + attack + " should be BLOCKED in CLASSICAL-HARDENED mode")
                    .isFalse();
            assertThat(hardened.defenceTriggered())
                    .as("Defence should be triggered in CLASSICAL-HARDENED mode")
                    .isTrue();
            assertThat(hardened.eventId())
                    .as("DetectionEvent id must be recorded for " + attack + " in CLASSICAL-HARDENED mode")
                    .isNotBlank();
            assertThat(hardened.detail())
                    .as("Detail must not contain [VULN- for " + attack)
                    .doesNotContain("[VULN-");

            // 3. HYBRID: Attack must be BLOCKED, defence TRIGGERED, eventId recorded
            SecurityMatrixResult hybrid = findResult(matrix, attack, "HYBRID");
            assertThat(hybrid).isNotNull();
            assertThat(hybrid.attackSucceeded())
                    .as("Attack " + attack + " should be BLOCKED in HYBRID mode")
                    .isFalse();
            assertThat(hybrid.defenceTriggered())
                    .as("Defence should be triggered in HYBRID mode")
                    .isTrue();
            assertThat(hybrid.eventId())
                    .as("DetectionEvent id must be recorded for " + attack + " in HYBRID mode")
                    .isNotBlank();
        }
    }

    // ── Mutation-Style Tests (Guards Disabled By Config) ─────────────────────

    @Test
    @DisplayName("Mutation: Downgrade attack succeeds when skipSuiteSignature=true")
    void mutationDowngradeSucceedsWhenGuardDisabled() throws Exception {
        HandshakeConfig cfg = HandshakeConfig.vulnerable();
        assertThat(cfg.isSkipSuiteSignature()).isTrue();

        AttackResult result = DowngradeAttack.execute(true);
        assertThat(result.success())
                .as("Downgrade attack MUST succeed when suite signature guard is mutated to disabled")
                .isTrue();
    }

    @Test
    @DisplayName("Mutation: MITM attack succeeds when skipKeyPinning=true")
    void mutationMitmSucceedsWhenGuardDisabled() throws Exception {
        HandshakeConfig cfg = HandshakeConfig.vulnerable();
        assertThat(cfg.isSkipKeyPinning()).isTrue();

        AttackResult result = MitmAttack.execute(true);
        assertThat(result.success())
                .as("MITM attack MUST succeed when key pinning guard is mutated to disabled")
                .isTrue();
    }

    @Test
    @DisplayName("Mutation: Replay attack succeeds when skipSequenceCheck=true")
    void mutationReplaySucceedsWhenGuardDisabled() throws Exception {
        HandshakeConfig cfg = HandshakeConfig.vulnerable();
        assertThat(cfg.isSkipSequenceCheck()).isTrue();

        AttackResult result = ReplayAttack.execute(true);
        assertThat(result.success())
                .as("Replay attack MUST succeed when sequence number validation guard is mutated to disabled")
                .isTrue();
    }

    @Test
    @DisplayName("Mutation: Nonce Reuse attack succeeds when unsafeNonceMode=true")
    void mutationNonceReuseSucceedsWhenGuardDisabled() throws Exception {
        HandshakeConfig cfg = HandshakeConfig.vulnerable();
        assertThat(cfg.isUnsafeNonceMode()).isTrue();

        AttackResult result = NonceReuseAttack.execute();
        assertThat(result.success())
                .as("Nonce reuse keystream leak MUST succeed when nonce guard is mutated to disabled")
                .isTrue();
    }

    @Test
    @DisplayName("Assert that no [VULN-] warnings are emitted in any CLASSICAL-HARDENED cell")
    void testNoVulnWarningsInClassicalHardenedCells() throws Exception {
        SecurityMatrixRunner runner = new SecurityMatrixRunner();
        List<String> attacks = List.of("Downgrade", "MITM", "Replay", "Nonce Reuse", "Tampering");
        for (String attack : attacks) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.PrintStream origOut = System.out;
            java.io.PrintStream tee = new java.io.PrintStream(new java.io.OutputStream() {
                @Override public void write(int b) { origOut.write(b); baos.write(b); }
                @Override public void write(byte[] b, int off, int len) { origOut.write(b, off, len); baos.write(b, off, len); }
                @Override public void flush() { origOut.flush(); }
            });
            System.setOut(tee);
            try {
                switch (attack) {
                    case "Downgrade" -> runner.runDowngrade("CLASSICAL-HARDENED");
                    case "MITM" -> runner.runMitm("CLASSICAL-HARDENED");
                    case "Replay" -> runner.runReplay("CLASSICAL-HARDENED");
                    case "Nonce Reuse" -> runner.runNonceReuse("CLASSICAL-HARDENED");
                    case "Tampering" -> runner.runTampering("CLASSICAL-HARDENED");
                }
            } finally {
                System.setOut(origOut);
            }
            String output = baos.toString(java.nio.charset.StandardCharsets.UTF_8);
            assertThat(output)
                    .as("No [VULN- text should be emitted in CLASSICAL-HARDENED cell for " + attack)
                    .doesNotContain("[VULN-");
        }
    }

    @Test
    @DisplayName("Verify DOWNGRADE/HYBRID policy enforcement vs signed transcript verification")
    void testHybridDowngradeBothControls() throws Exception {
        SecurityMatrixRunner runner = new SecurityMatrixRunner();
        // Control 1: rejectClassical=true -> server policy enforcement blocks it
        boolean policyResult = runner.executeHybridDowngrade(true);
        assertThat(policyResult).isFalse();

        // Control 2: rejectClassical=false -> client ML-DSA-65 signed transcript mismatch blocks it
        boolean transcriptResult = runner.executeHybridDowngrade(false);
        assertThat(transcriptResult).isFalse();
    }

    private SecurityMatrixResult findResult(List<SecurityMatrixResult> matrix, String attack, String mode) {
        return matrix.stream()
                .filter(r -> r.attack().equalsIgnoreCase(attack) && r.mode().equalsIgnoreCase(mode))
                .findFirst()
                .orElse(null);
    }
}
