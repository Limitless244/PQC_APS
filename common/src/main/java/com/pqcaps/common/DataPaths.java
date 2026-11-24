package com.pqcaps.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Centralized data directory resolver for generated reports and logs.
 *
 * <p>Configurable via the system property {@code pqcaps.dataDir} (defaulting to {@code data}).
 * Automatically detects repository root when executed from subproject working directories.
 */
public final class DataPaths {

    private DataPaths() {}

    /**
     * Resolves the project root directory by searching upward for pom.xml and root markers.
     */
    public static Path getProjectRoot() {
        Path current = Path.of("").toAbsolutePath();
        while (current != null) {
            if (Files.exists(current.resolve("pom.xml")) &&
                (Files.exists(current.resolve("samples")) || Files.exists(current.resolve("benchmark-dashboard")))) {
                return current;
            }
            current = current.getParent();
        }
        return Path.of("").toAbsolutePath();
    }

    /**
     * Resolves the configured data directory (e.g. "<projectRoot>/data").
     */
    public static Path getDataDir() {
        String prop = System.getProperty("pqcaps.dataDir", "data");
        Path p = Path.of(prop);
        if (p.isAbsolute()) {
            return p;
        }
        return getProjectRoot().resolve(prop);
    }

    /**
     * Resolves a file inside the configured data directory, creating parent directories if needed.
     */
    public static Path resolve(String filename) {
        Path dir = getDataDir();
        try {
            Files.createDirectories(dir);
        } catch (IOException ignored) {}
        return dir.resolve(filename);
    }
}
