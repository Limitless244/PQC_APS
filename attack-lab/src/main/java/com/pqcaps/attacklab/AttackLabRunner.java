package com.pqcaps.attacklab;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line runner for the attack lab demonstrations.
 *
 * <p>Usage:
 * <pre>
 *   java -jar attack-lab.jar &lt;downgrade|mitm|replay|nonce|all&gt;
 * </pre>
 *
 * <p>Executes the specified attack(s) against the vulnerable Phase 1 baseline,
 * prints step-by-step console narration, and records results into {@code attack-results.json}.
 */
public final class AttackLabRunner {

    private static final String DEFAULT_JSON_PATH = com.pqcaps.common.DataPaths.resolve("attack-results.json").toString();

    public static void main(String[] args) {
        String target = (args != null && args.length > 0) ? args[0].toLowerCase().trim() : "all";

        System.out.println("======================================================================");
        System.out.println("  PQC-APS :: Attack Lab Runner (Phase 2 Baseline Exploitation)");
        System.out.println("  Target Command: " + target);
        System.out.println("======================================================================\n");

        List<AttackResult> results = new ArrayList<>();

        switch (target) {
            case "downgrade" -> {
                System.out.println(">>> Executing ATTACK 1: Cipher Suite Downgrade (VULN-1)...");
                results.add(DowngradeAttack.execute(true));
            }
            case "mitm" -> {
                System.out.println(">>> Executing ATTACK 2: Man-In-The-Middle Eavesdropping (VULN-4)...");
                results.add(MitmAttack.execute(true));
            }
            case "replay" -> {
                System.out.println(">>> Executing ATTACK 3: Transaction Record Replay (VULN-2)...");
                results.add(ReplayAttack.execute(true));
            }
            case "nonce" -> {
                System.out.println(">>> Executing ATTACK 4: AES-GCM Nonce Reuse Keystream Leak (VULN-3)...");
                results.add(NonceReuseAttack.execute());
            }
            case "matrix" -> {
                System.out.println(">>> Executing Full Security Matrix (5 attacks x 3 modes)...");
                SecurityMatrixRunner matrixRunner = new SecurityMatrixRunner();
                List<SecurityMatrixResult> matrixResults = matrixRunner.runFullMatrix();
                SecurityMatrixRunner.printMatrixTable(matrixResults);
                File matrixFile = new File(DEFAULT_JSON_PATH);
                try {
                    SecurityMatrixResult.saveToJson(matrixFile, matrixResults);
                    System.out.println("[INFO] Wrote security matrix results to: " + matrixFile.getAbsolutePath());
                } catch (IOException e) {
                    System.err.println("[WARN] Failed to write " + DEFAULT_JSON_PATH + ": " + e.getMessage());
                }
                return;
            }
            case "all" -> {
                System.out.println(">>> [1/4] Executing ATTACK 1: Cipher Suite Downgrade (VULN-1)...");
                results.add(DowngradeAttack.execute(true));
                System.out.println("\n>>> [2/4] Executing ATTACK 2: Man-In-The-Middle Eavesdropping (VULN-4)...");
                results.add(MitmAttack.execute(true));
                System.out.println("\n>>> [3/4] Executing ATTACK 3: Transaction Record Replay (VULN-2)...");
                results.add(ReplayAttack.execute(true));
                System.out.println("\n>>> [4/4] Executing ATTACK 4: AES-GCM Nonce Reuse Keystream Leak (VULN-3)...");
                results.add(NonceReuseAttack.execute());

                System.out.println("\n>>> [5/5] Executing Full Security Matrix (5 attacks x 3 modes)...");
                SecurityMatrixRunner matrixRunner = new SecurityMatrixRunner();
                List<SecurityMatrixResult> matrixResults = matrixRunner.runFullMatrix();
                SecurityMatrixRunner.printMatrixTable(matrixResults);
                File matrixFile = new File(DEFAULT_JSON_PATH);
                try {
                    SecurityMatrixResult.saveToJson(matrixFile, matrixResults);
                    System.out.println("[INFO] Wrote security matrix results to: " + matrixFile.getAbsolutePath());
                } catch (IOException e) {
                    System.err.println("[WARN] Failed to write " + DEFAULT_JSON_PATH + ": " + e.getMessage());
                }
                return;
            }
            default -> {
                System.err.println("Unknown command: '" + target + "'. Valid options: downgrade, mitm, replay, nonce, matrix, all");
                System.exit(1);
            }
        }

        // Output summary table
        System.out.println("\n======================================================================");
        System.out.println("  ATTACK LAB EXECUTION SUMMARY");
        System.out.println("======================================================================");
        for (AttackResult r : results) {
            System.out.printf("[%s] %-25s -> Success: %-5b | Vuln: %s%n",
                    r.success() ? "EXPLOITED" : "BLOCKED", r.name(), r.success(), r.vulnerabilityId());
        }

        // Save to attack-results.json
        File jsonFile = new File(DEFAULT_JSON_PATH);
        try {
            AttackResult.saveToJson(jsonFile, results);
            System.out.println("\n[INFO] Wrote attack results to: " + jsonFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("[WARN] Failed to write " + DEFAULT_JSON_PATH + ": " + e.getMessage());
        }
    }
}
