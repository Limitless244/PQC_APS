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
     * Resolves the configured data directory (e.g. "data" or "../data").
     */
    public static Path getDataDir() {
        String prop = System.getProperty("pqcaps.dataDir", "data");
        Path p = Path.of(prop);
        if (Files.exists(p) && Files.isDirectory(p)) {
            return p;
        }
        // If running from inside a subproject, check if parent directory has dataDir or pom.xml
        Path parentData = Path.of("..", prop);
        if (Files.exists(parentData) && Files.isDirectory(parentData)) {
            return parentData;
        }
        if (Files.exists(Path.of("..", "pom.xml"))) {
            return parentData;
        }
        return p;
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
