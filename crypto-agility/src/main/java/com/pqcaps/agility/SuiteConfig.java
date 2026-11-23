package com.pqcaps.agility;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * Loads algorithm suite configuration from {@code suites.yaml} on the classpath.
 *
 * <p>All algorithm name strings (e.g. "ML-KEM-768") are stored here, never
 * scattered through the codebase. Any crypto primitive class that needs an
 * algorithm name calls {@code SuiteConfig.forSuite(suite).getKemAlgorithm()}
 * rather than writing a literal string.
 */
public final class SuiteConfig {

    private static final Map<AlgorithmSuite, SuiteConfig> CONFIGS = loadConfigs();

    private final AlgorithmSuite suite;
    private final String kemAlgorithm;
    private final String classicalKemAlgorithm;
    private final String signatureAlgorithm;
    private final String symmetricAlgorithm;
    private final int    symmetricKeyBits;
    private final String kdfAlgorithm;

    private SuiteConfig(
            AlgorithmSuite suite,
            String kemAlgorithm,
            String classicalKemAlgorithm,
            String signatureAlgorithm,
            String symmetricAlgorithm,
            int    symmetricKeyBits,
            String kdfAlgorithm) {
        this.suite                 = suite;
        this.kemAlgorithm          = kemAlgorithm;
        this.classicalKemAlgorithm = classicalKemAlgorithm;
        this.signatureAlgorithm    = signatureAlgorithm;
        this.symmetricAlgorithm    = symmetricAlgorithm;
        this.symmetricKeyBits      = symmetricKeyBits;
        this.kdfAlgorithm          = kdfAlgorithm;
    }

    @SuppressWarnings("unchecked")
    private static Map<AlgorithmSuite, SuiteConfig> loadConfigs() {
        Map<AlgorithmSuite, SuiteConfig> map = new EnumMap<>(AlgorithmSuite.class);
        try (InputStream in = SuiteConfig.class.getClassLoader().getResourceAsStream("suites.yaml")) {
            if (in != null) {
                Yaml yaml = new Yaml();
                Map<String, Object> data = yaml.load(in);
                if (data != null && data.containsKey("suites")) {
                    Map<String, Object> suitesMap = (Map<String, Object>) data.get("suites");
                    for (AlgorithmSuite suite : AlgorithmSuite.values()) {
                        Map<String, Object> cfg = (Map<String, Object>) suitesMap.get(suite.name());
                        if (cfg != null) {
                            String kem = (String) cfg.get("kemAlgorithm");
                            String classicalKem = (String) cfg.get("classicalKemAlgorithm");
                            String sig = (String) cfg.get("signatureAlgorithm");
                            String sym = (String) cfg.get("symmetricAlgorithm");
                            Number bits = (Number) cfg.get("symmetricKeyBits");
                            String kdf = (String) cfg.get("kdfAlgorithm");

                            map.put(suite, new SuiteConfig(
                                    suite, kem, classicalKem, sig, sym,
                                    bits != null ? bits.intValue() : 256,
                                    kdf
                            ));
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // Fall back to defaults below
        }

        // Ensure all suites are populated with defaults if missing
        for (AlgorithmSuite suite : AlgorithmSuite.values()) {
            map.putIfAbsent(suite, createDefault(suite));
        }

        return Collections.unmodifiableMap(map);
    }

    private static SuiteConfig createDefault(AlgorithmSuite suite) {
        return switch (suite) {
            case CLASSICAL -> new SuiteConfig(
                    suite,
                    /* kem          */ "XDH",
                    /* classicalKem */ "XDH",
                    /* sig          */ "SHA256withECDSA",
                    /* sym          */ "AES/GCM/NoPadding",
                    /* keyBits      */ 256,
                    /* kdf          */ "HkdfSHA256");

            case HYBRID -> new SuiteConfig(
                    suite,
                    /* kem          */ "ML-KEM-768",
                    /* classicalKem */ "XDH",
                    /* sig          */ "ML-DSA-65",
                    /* sym          */ "AES/GCM/NoPadding",
                    /* keyBits      */ 256,
                    /* kdf          */ "HkdfSHA256");

            case PQ_ONLY -> new SuiteConfig(
                    suite,
                    /* kem          */ "ML-KEM-768",
                    /* classicalKem */ null,
                    /* sig          */ "ML-DSA-65",
                    /* sym          */ "AES/GCM/NoPadding",
                    /* keyBits      */ 256,
                    /* kdf          */ "HkdfSHA256");
        };
    }

    // ── Factory ──────────────────────────────────────────────────────────────

    /**
     * Returns the configuration for the given suite loaded from {@code suites.yaml}.
     *
     * @param suite the desired algorithm suite
     * @return a fully-populated SuiteConfig
     */
    public static SuiteConfig forSuite(AlgorithmSuite suite) {
        return CONFIGS.getOrDefault(suite, createDefault(suite));
    }

    /**
     * Returns the configuration for the given suite name (case-insensitive).
     *
     * @param suiteName the suite name (e.g. "HYBRID")
     * @return a fully-populated SuiteConfig
     */
    public static SuiteConfig forSuite(String suiteName) {
        return forSuite(AlgorithmSuite.valueOf(suiteName.trim().toUpperCase()));
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    /** The selected {@link AlgorithmSuite}. */
    public AlgorithmSuite getSuite()                { return suite; }

    /** Post-quantum KEM algorithm name (e.g. "ML-KEM-768"). */
    public String getKemAlgorithm()                 { return kemAlgorithm; }

    /** Classical KEM algorithm name (e.g. "XDH" for X25519), or {@code null} for PQ_ONLY. */
    public String getClassicalKemAlgorithm()        { return classicalKemAlgorithm; }

    /** Signature algorithm name (e.g. "ML-DSA-65" or "SHA256withECDSA"). */
    public String getSignatureAlgorithm()           { return signatureAlgorithm; }

    /** Symmetric AEAD algorithm name (always "AES/GCM/NoPadding" in this project). */
    public String getSymmetricAlgorithm()           { return symmetricAlgorithm; }

    /** Symmetric key size in bits (always 256 in this project). */
    public int getSymmetricKeyBits()                { return symmetricKeyBits; }

    /** Key derivation function name (always "HkdfSHA256" in this project). */
    public String getKdfAlgorithm()                 { return kdfAlgorithm; }
}
