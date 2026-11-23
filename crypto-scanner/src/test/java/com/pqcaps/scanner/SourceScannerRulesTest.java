package com.pqcaps.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Source Scanner Rule Detection Tests")
class SourceScannerRulesTest {

    @TempDir
    Path tempDir;

    private final SourceScanner scanner = new SourceScanner();

    @Test
    @DisplayName("RULE-RSA: Detects standard RSA and marks quantum-vulnerable")
    void testRsaDetection() throws IOException {
        Path f = tempDir.resolve("RsaTest.java");
        Files.writeString(f, """
            public class RsaTest {
                void gen() throws Exception {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(2048);
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("RULE-RSA");
        assertThat(findings.get(0).quantumVulnerable()).isTrue();
        assertThat(findings.get(0).algorithm()).isEqualTo("RSA-2048");
    }

    @Test
    @DisplayName("RULE-RSA-WEAK: Flags RSA < 2048 as CRITICAL")
    void testWeakRsaDetection() throws IOException {
        Path f = tempDir.resolve("WeakRsaTest.java");
        Files.writeString(f, """
            public class WeakRsaTest {
                void gen() throws Exception {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(1024);
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("RULE-RSA-WEAK");
        assertThat(findings.get(0).severity()).isEqualTo("CRITICAL");
        assertThat(findings.get(0).riskScore()).isEqualTo(95);
    }

    @Test
    @DisplayName("RULE-ECC: Detects X25519, ECDH, ECDSA")
    void testEccDetection() throws IOException {
        Path f = tempDir.resolve("EccTest.java");
        Files.writeString(f, """
            public class EccTest {
                void test() throws Exception {
                    KeyAgreement ka = KeyAgreement.getInstance("X25519");
                    Signature sig = Signature.getInstance("SHA256withECDSA");
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(find -> find.ruleId().equals("RULE-ECC") && find.quantumVulnerable());
    }

    @Test
    @DisplayName("RULE-DH-DSA: Detects Diffie-Hellman and DSA")
    void testDhDsaDetection() throws IOException {
        Path f = tempDir.resolve("DhTest.java");
        Files.writeString(f, """
            public class DhTest {
                void test() throws Exception {
                    KeyPairGenerator dh = KeyPairGenerator.getInstance("DiffieHellman");
                    Signature dsa = Signature.getInstance("SHA256withDSA");
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(find -> find.ruleId().equals("RULE-DH-DSA") && find.quantumVulnerable());
    }

    @Test
    @DisplayName("RULE-MD5 & RULE-SHA1: Detects broken hashes")
    void testBrokenHashes() throws IOException {
        Path f = tempDir.resolve("HashTest.java");
        Files.writeString(f, """
            public class HashTest {
                void test() throws Exception {
                    MessageDigest md5 = MessageDigest.getInstance("MD5");
                    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(2);
        assertThat(findings.stream().anyMatch(fnd -> fnd.ruleId().equals("RULE-MD5"))).isTrue();
        assertThat(findings.stream().anyMatch(fnd -> fnd.ruleId().equals("RULE-SHA1"))).isTrue();
    }

    @Test
    @DisplayName("Negative Test for Hashes: SHA-256 and SHA-384 are NOT flagged")
    void testSecureHashNegative() throws IOException {
        Path f = tempDir.resolve("SecureHashTest.java");
        Files.writeString(f, """
            public class SecureHashTest {
                void test() throws Exception {
                    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                    MessageDigest sha384 = MessageDigest.getInstance("SHA-384");
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("RULE-DES-3DES, RULE-RC4-BLOWFISH, RULE-AES-ECB: Detects deprecated ciphers")
    void testDeprecatedCiphers() throws IOException {
        Path f = tempDir.resolve("CipherTest.java");
        Files.writeString(f, """
            public class CipherTest {
                void test() throws Exception {
                    Cipher c1 = Cipher.getInstance("DES/CBC/PKCS5Padding");
                    Cipher c2 = Cipher.getInstance("RC4");
                    Cipher c3 = Cipher.getInstance("AES/ECB/PKCS5Padding");
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(3);
        assertThat(findings.stream().anyMatch(fnd -> fnd.ruleId().equals("RULE-DES-3DES"))).isTrue();
        assertThat(findings.stream().anyMatch(fnd -> fnd.ruleId().equals("RULE-RC4-BLOWFISH"))).isTrue();
        assertThat(findings.stream().anyMatch(fnd -> fnd.ruleId().equals("RULE-AES-ECB"))).isTrue();
    }

    @Test
    @DisplayName("RULE-AES128: Detects AES with 128-bit key as INFO")
    void testAes128Detection() throws IOException {
        Path f = tempDir.resolve("Aes128Test.java");
        Files.writeString(f, """
            public class Aes128Test {
                void test() throws Exception {
                    KeyGenerator kg = KeyGenerator.getInstance("AES");
                    kg.init(128);
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("RULE-AES128");
        assertThat(findings.get(0).severity()).isEqualTo("INFO");
        assertThat(findings.get(0).riskScore()).isEqualTo(20);
    }

    @Test
    @DisplayName("RULE-HARDCODED-SECRET: Detects and redacts credentials in source")
    void testHardcodedSecret() throws IOException {
        Path f = tempDir.resolve("SecretTest.java");
        Files.writeString(f, """
            public class SecretTest {
                private static final String API_SECRET = "DUMMY_SECRET_KEY_1234567890_EXAMP";
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("RULE-HARDCODED-SECRET");
        assertThat(findings.get(0).redactedSnippet()).doesNotContain("DUMMY_SECRET_KEY_1234567890_EXAMP");
        assertThat(findings.get(0).redactedSnippet()).contains("DUMM****");
    }

    @Test
    @DisplayName("RULE-WEAK-RNG: Detects java.util.Random used near secret keys")
    void testWeakRng() throws IOException {
        Path f = tempDir.resolve("RngTest.java");
        Files.writeString(f, """
            public class RngTest {
                void gen() {
                    java.util.Random random = new java.util.Random();
                    byte[] key = new byte[16];
                    random.nextBytes(key);
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("RULE-WEAK-RNG");
    }

    @Test
    @DisplayName("Negative Test for RNG: java.security.SecureRandom is NOT flagged")
    void testSecureRngNegative() throws IOException {
        Path f = tempDir.resolve("SecureRngTest.java");
        Files.writeString(f, """
            public class SecureRngTest {
                void gen() {
                    java.security.SecureRandom csprng = new java.security.SecureRandom();
                    byte[] key = new byte[32];
                    csprng.nextBytes(key);
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).isEmpty();
    }

    @Test
    @DisplayName("RULE-STATIC-IV: Detects static/zero IV allocation")
    void testStaticIv() throws IOException {
        Path f = tempDir.resolve("StaticIvTest.java");
        Files.writeString(f, """
            public class StaticIvTest {
                void enc() {
                    byte[] iv = new byte[12];
                    GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).isNotEmpty();
        assertThat(findings.get(0).ruleId()).isEqualTo("RULE-STATIC-IV");
    }

    @Test
    @DisplayName("RULE-PQC-READY: Detects ML-KEM and ML-DSA as positive adoption (score=0)")
    void testPqcReadyDetection() throws IOException {
        Path f = tempDir.resolve("PqcTest.java");
        Files.writeString(f, """
            public class PqcTest {
                void test() throws Exception {
                    KeyPairGenerator kem = KeyPairGenerator.getInstance("ML-KEM-768");
                    Signature sig = Signature.getInstance("ML-DSA-65");
                }
            }
            """);

        List<ScanFinding> findings = scanner.scanSingleFile(tempDir, f);
        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(fnd -> fnd.ruleId().equals("RULE-PQC-READY") && fnd.riskScore() == 0);
    }
}
