package com.pqcaps.attack;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Enforces high-entropy CSPRNG usage for all secret material and nonces.
 *
 * <p>Linear congruential PRNGs (such as {@link java.util.Random}) are completely
 * predictable after observing a few outputs. {@code RandomnessGuard} enforces
 * {@link SecureRandom} and provides static code analysis to detect accidental
 * usage of weak PRNGs.
 */
public final class RandomnessGuard {

    private static final Pattern WEAK_RANDOM_IMPORT =
            Pattern.compile("import\\s+java\\.util\\.Random;");
    private static final Pattern WEAK_RANDOM_NEW =
            Pattern.compile("new\\s+java\\.util\\.Random\\s*\\(");
    private static final Pattern WEAK_MATH_RANDOM =
            Pattern.compile("Math\\.random\\s*\\(");

    private final EventLog eventLog;

    public RandomnessGuard() {
        this(EventLog.getInstance());
    }

    public RandomnessGuard(EventLog eventLog) {
        this.eventLog = eventLog;
    }

    /**
     * Centralized provider of cryptographically secure random bytes.
     */
    public static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            return new SecureRandom();
        }
    }

    /**
     * Scans project source files to ensure no cryptographic secrets use weak PRNGs.
     */
    public List<String> scanSourceDirectory(Path sourceDir) throws IOException {
        List<String> violations = new ArrayList<>();
        if (!Files.exists(sourceDir)) {
            return violations;
        }

        try (Stream<Path> stream = Files.walk(sourceDir)) {
            List<Path> javaFiles = stream
                    .filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .toList();

            for (Path file : javaFiles) {
                List<String> lines = Files.readAllLines(file);
                for (int lineNum = 1; lineNum <= lines.size(); lineNum++) {
                    String line = lines.get(lineNum - 1);
                    if (WEAK_RANDOM_IMPORT.matcher(line).find() ||
                        WEAK_RANDOM_NEW.matcher(line).find() ||
                        WEAK_MATH_RANDOM.matcher(line).find()) {

                        String violation = String.format("%s:%d -> %s", file.getFileName(), lineNum, line.trim());
                        violations.add(violation);
                        eventLog.record(
                                DetectionEvent.AttackType.WEAK_RANDOMNESS,
                                DetectionEvent.Severity.HIGH,
                                "RandomnessGuard",
                                "GENERAL",
                                DetectionEvent.Action.BLOCKED,
                                "Insecure random generator detected in source: " + violation
                        );
                    }
                }
            }
        }
        return violations;
    }
}
