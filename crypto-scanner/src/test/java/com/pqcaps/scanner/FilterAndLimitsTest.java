package com.pqcaps.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Scanner Filters and Limits Tests")
class FilterAndLimitsTest {

    @TempDir
    Path tempDir;

    private final SourceScanner scanner = new SourceScanner();

    @Test
    @DisplayName("Ignored directories (target/, .git/, node_modules/) are skipped")
    void testIgnoredDirectories() throws IOException {
        Path targetDir = Files.createDirectories(tempDir.resolve("target"));
        Path gitDir = Files.createDirectories(tempDir.resolve(".git"));
        Path nodeDir = Files.createDirectories(tempDir.resolve("node_modules"));
        Path srcDir = Files.createDirectories(tempDir.resolve("src"));

        // Put vulnerable files inside ignored directories
        Files.writeString(targetDir.resolve("TargetBad.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(gitDir.resolve("GitBad.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(nodeDir.resolve("NodeBad.js"), "const des = 'DES';");

        // Put one valid finding in srcDir
        Files.writeString(srcDir.resolve("GoodScan.java"), "Cipher c = Cipher.getInstance(\"DES\");");

        List<ScanFinding> findings = scanner.scanDirectory(tempDir);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).file()).contains("src/GoodScan.java");
    }

    @Test
    @DisplayName("Files exceeding 1 MB are skipped")
    void testFileOverSizeLimitSkipped() throws IOException {
        Path bigFile = tempDir.resolve("BigFile.java");
        byte[] bigContent = new byte[1_048_577]; // 1 MB + 1 byte
        java.util.Arrays.fill(bigContent, (byte) 'A');
        Files.write(bigFile, bigContent);

        List<ScanFinding> findings = scanner.scanDirectory(tempDir);
        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("Binary files (containing 0x00) are skipped")
    void testBinaryFilesSkipped() throws IOException {
        Path binFile = tempDir.resolve("binary.java");
        byte[] binData = new byte[]{0x41, 0x42, 0x00, 0x43, 0x44};
        Files.write(binFile, binData);

        List<ScanFinding> findings = scanner.scanDirectory(tempDir);
        assertThat(findings).isEmpty();
    }
}
