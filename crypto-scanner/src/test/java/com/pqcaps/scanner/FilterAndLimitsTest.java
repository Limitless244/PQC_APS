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
    @DisplayName("Ignored directories (target/, .git/, node_modules/, data/, samples/) are skipped by default, overridable by includeSamples")
    void testIgnoredDirectories() throws IOException {
        Path targetDir = Files.createDirectories(tempDir.resolve("target"));
        Path gitDir = Files.createDirectories(tempDir.resolve(".git"));
        Path nodeDir = Files.createDirectories(tempDir.resolve("node_modules"));
        Path dataDir = Files.createDirectories(tempDir.resolve("data"));
        Path samplesDir = Files.createDirectories(tempDir.resolve("samples"));
        Path srcDir = Files.createDirectories(tempDir.resolve("src"));

        // Put vulnerable files inside ignored directories
        Files.writeString(targetDir.resolve("TargetBad.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(gitDir.resolve("GitBad.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(nodeDir.resolve("NodeBad.js"), "const des = 'DES';");
        Files.writeString(dataDir.resolve("DataBad.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(samplesDir.resolve("SamplesBad.java"), "Cipher c = Cipher.getInstance(\"DES\");");

        // Put one valid finding in srcDir
        Files.writeString(srcDir.resolve("GoodScan.java"), "Cipher c = Cipher.getInstance(\"DES\");");

        // Default scanner ignores samples/ and data/ as well
        List<ScanFinding> findings = scanner.scanDirectory(tempDir);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).file()).contains("src/GoodScan.java");

        // Scanner with includeSamples = true includes samples/
        SourceScanner scannerWithSamples = new SourceScanner(true);
        List<ScanFinding> findingsWithSamples = scannerWithSamples.scanDirectory(tempDir);
        assertThat(findingsWithSamples).hasSize(2);
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

    @Test
    @DisplayName("src/test/ and rules.yaml are excluded by default, overridable by includeTests")
    void testSrcTestAndRulesYamlExclusion() throws IOException {
        Path testSubDir = Files.createDirectories(tempDir.resolve("module-a/src/test/java"));
        Path mainSubDir = Files.createDirectories(tempDir.resolve("module-a/src/main/java"));
        Path rulesFile = tempDir.resolve("rules.yaml");

        Files.writeString(testSubDir.resolve("VulnerableTest.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(mainSubDir.resolve("ProductionCode.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(rulesFile, "id: RULE-DES-3DES\nalgorithm: DES\n");

        // Default scanner excludes src/test/ and rules.yaml
        List<ScanFinding> defaultFindings = scanner.scanDirectory(tempDir);
        assertThat(defaultFindings).hasSize(1);
        assertThat(defaultFindings.get(0).file()).contains("src/main/java/ProductionCode.java");

        // Scanner with includeTests = true includes src/test/ and rules.yaml
        SourceScanner testScanner = new SourceScanner(RuleRegistry.getInstance(), 10, false, true, java.util.Set.of());
        List<ScanFinding> testFindings = testScanner.scanDirectory(tempDir);
        assertThat(testFindings).hasSize(3);
    }

    @Test
    @DisplayName("XML <description> and <name> tags are ignored during scan")
    void testXmlDescriptionAndNameTagsIgnored() throws IOException {
        Path xmlFile = tempDir.resolve("test-pom.xml");
        String xmlContent = """
            <project>
                <name>DES Test</name>
                <description>
                    PQC-APS classical cryptographic components with DES/3DES legacy cipher support.
                </description>
                <properties>
                    <legacy.cipher>DES</legacy.cipher>
                </properties>
            </project>
            """;
        Files.writeString(xmlFile, xmlContent);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, xmlFile);
        // Only <legacy.cipher>DES</legacy.cipher> should match RULE-DES-3DES; <name> and <description> ignored
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).redactedSnippet()).contains("<legacy.cipher>DES</legacy.cipher>");
    }

    @Test
    @DisplayName("Redaction template constant is ignored while real PEM private key is detected")
    void testRedactionTemplateIgnored() throws IOException {
        Path javaFile = tempDir.resolve("KeySnippet.java");
        String javaContent = """
            public class KeySnippet {
                public static final String TEMPLATE = "-----BEGIN PRIVATE KEY----- [REDACTED]";
                public static final String REAL_KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBg...";
            }
            """;
        Files.writeString(javaFile, javaContent);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, javaFile);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).line()).isEqualTo(3);
        assertThat(findings.get(0).algorithm()).isEqualTo("PEM_PRIVATE_KEY");
    }

    @Test
    @DisplayName("--exclude-modules flag skips specified directories")
    void testExcludeModules() throws IOException {
        Path attackLabDir = Files.createDirectories(tempDir.resolve("attack-lab"));
        Path classicalDir = Files.createDirectories(tempDir.resolve("classical"));
        Path agilityDir = Files.createDirectories(tempDir.resolve("crypto-agility"));

        Files.writeString(attackLabDir.resolve("AttackTarget.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(classicalDir.resolve("LegacyCipher.java"), "Cipher c = Cipher.getInstance(\"DES\");");
        Files.writeString(agilityDir.resolve("AgileCipher.java"), "Cipher c = Cipher.getInstance(\"DES\");");

        SourceScanner moduleExcludingScanner = new SourceScanner(
                RuleRegistry.getInstance(), 10, false, false, java.util.Set.of("attack-lab", "classical")
        );

        List<ScanFinding> findings = moduleExcludingScanner.scanDirectory(tempDir);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).file()).contains("crypto-agility/AgileCipher.java");
    }
}
