package com.pqcaps.agility;

import java.util.Objects;

/**
 * Registry for looking up and validating algorithm suites.
 *
 * <p>Enforces server migration policies, such as rejecting legacy classical suites
 * when post-quantum enforcement is active:
 * <pre>{@code
 * SuiteRegistry registry = new SuiteRegistry(true); // rejectClassical = true
 * registry.resolveSuite("CLASSICAL"); // Throws SecurityException
 * registry.resolveSuite("HYBRID");    // Allowed
 * }</pre>
 */
public final class SuiteRegistry {

    private final boolean rejectClassical;

    /**
     * Creates a default registry that allows all suites.
     */
    public SuiteRegistry() {
        this(false);
    }

    /**
     * Creates a registry with an explicit policy flag.
     *
     * @param rejectClassical if {@code true}, requests for "CLASSICAL" will be rejected
     */
    public SuiteRegistry(boolean rejectClassical) {
        this.rejectClassical = rejectClassical;
    }

    public boolean isRejectClassical() {
        return rejectClassical;
    }

    /**
     * Resolves and validates a suite by name.
     *
     * @param name suite identifier (e.g. "HYBRID", "PQ_ONLY", "CLASSICAL")
     * @return configured {@link SuiteConfig}
     * @throws SecurityException if the suite is CLASSICAL and rejectClassical is true
     * @throws IllegalArgumentException if the suite is unknown
     */
    public SuiteConfig resolveSuite(String name) {
        Objects.requireNonNull(name, "Suite name cannot be null");
        AlgorithmSuite suite;
        try {
            suite = AlgorithmSuite.valueOf(name.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown algorithm suite: " + name);
        }
        return resolveSuite(suite);
    }

    /**
     * Validates and returns configuration for an {@link AlgorithmSuite}.
     *
     * @param suite target suite
     * @return configured {@link SuiteConfig}
     * @throws SecurityException if the suite is CLASSICAL and rejectClassical is true
     */
    public SuiteConfig resolveSuite(AlgorithmSuite suite) {
        Objects.requireNonNull(suite, "Algorithm suite cannot be null");
        if (suite == AlgorithmSuite.CLASSICAL && rejectClassical) {
            throw new SecurityException(
                    "Classical cipher suite 'CLASSICAL' is rejected by security policy (rejectClassical=true)");
        }
        return SuiteConfig.forSuite(suite);
    }
}
