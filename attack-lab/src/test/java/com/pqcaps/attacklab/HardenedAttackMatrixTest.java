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

        // Save to attack-results.json for inspection and Phase 6 dashboard
        File jsonFile = new File("attack-results.json");
        SecurityMatrixResult.saveToJson(jsonFile, matrix);
        assertThat(jsonFile).exists();

        // Also ensure copy exists at repo root if running from subproject directory
        File parentPom = new File("..", "pom.xml");
        if (parentPom.exists()) {
            File rootJson = new File("..", "attack-results.json");
            SecurityMatrixResult.saveToJson(rootJson, matrix);
            File localEvents = new File("detection-events.jsonl");
            if (localEvents.exists()) {
                java.nio.file.Files.copy(localEvents.toPath(), java.nio.file.Path.of("..", "detection-events.jsonl"),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }

        List<String> attacks = List.of("Downgrade", "MITM", "Replay", "Nonce Reuse", "Tampering");

        for (String attack : attacks) {
            // 1. CLASSICAL-VULNERABLE: Attack must SUCCEED, defence NOT triggered
            SecurityMatrixResult vuln = findResult(matrix, attack, "CLASSICAL-VULNERABLE");
            assertThat(vuln).isNotNull();
            assertThat(vuln.attackSucceeded())
                    .as("Attack " + attack + " should succeed in CLASSICAL-VULNERABLE mode")
                    .isTrue();
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

    private SecurityMatrixResult findResult(List<SecurityMatrixResult> matrix, String attack, String mode) {
        return matrix.stream()
                .filter(r -> r.attack().equalsIgnoreCase(attack) && r.mode().equalsIgnoreCase(mode))
                .findFirst()
                .orElse(null);
    }
}
