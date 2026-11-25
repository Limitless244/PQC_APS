package com.pqcaps.scanner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans source code and configuration files for cryptographic weaknesses,
 * quantum vulnerabilities, hardcoded secrets, and PQC adoption.
 */
public final class SourceScanner {

    private static final long MAX_FILE_SIZE = 1_048_576L; // 1 MB

    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
            "java", "py", "js", "ts", "properties", "yml", "yaml", "xml", "conf", "pem"
    );

    private static final Set<String> DEFAULT_IGNORED_DIRECTORIES = Set.of(
            "target", ".git", "node_modules", "data", ".m2", ".idea", ".vscode", "bin", "build", "dist"
    );

    // Java JCA getInstance pattern
    private static final Pattern JAVA_GET_INSTANCE_PATTERN = Pattern.compile(
            "(?:Cipher|KeyPairGenerator|KeyAgreement|Signature|MessageDigest|Mac|KeyGenerator|KeyFactory|SecureRandom)\\s*\\.\\s*getInstance\\s*\\(\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE
    );

    // Nearby key size initialization patterns: .initialize(1024), .init(1024)
    private static final Pattern KEY_SIZE_PATTERN = Pattern.compile(
            "\\.(?:initialize|init)\\s*\\(\\s*(\\d{3,5})\\b"
    );

    // Weak random patterns
    private static final Pattern JAVA_UTIL_RANDOM_PATTERN = Pattern.compile(
            "\\bnew\\s+(?:java\\.util\\.)?Random\\s*\\(|\\bMath\\.random\\s*\\(|\\brandom\\.random\\s*\\("
    );
    private static final Pattern SECURITY_CONTEXT_PATTERN = Pattern.compile(
            "(?i)\\b(?:key|nonce|iv|token|secret|salt|seed|password|credential)\\b"
    );

    // Static or zero IV patterns
    private static final Pattern STATIC_IV_PATTERN = Pattern.compile(
            "new\\s+(?:GCMParameterSpec\\s*\\([^,]+,|IvParameterSpec\\s*\\()\\s*new\\s+byte\\s*\\[\\s*(12|16)\\s*\\]|" +
            "byte\\s*\\[\\s*\\]\\s*(?:iv|nonce)\\s*=\\s*new\\s+byte\\s*\\[\\s*(12|16)\\s*\\]"
    );

    // Hardcoded secrets pattern
    private static final Pattern HARDCODED_SECRET_PATTERN = Pattern.compile(
            "(?i)[a-z0-9_]*(?:key|secret|password|passwd|token)[a-z0-9_]*\\s*[:=]\\s*[\"']([A-Za-z0-9+/=_-]{16,})[\"']"
    );

    private static final Pattern PEM_PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY-----"
    );

    private final RuleRegistry ruleRegistry;
    private final int dataLifetimeYears;
    private final boolean includeSamples;
    private final boolean includeTests;
    private final Set<String> excludedModules;

    public SourceScanner() {
        this(RuleRegistry.getInstance(), RiskScoreCalculator.DEFAULT_DATA_LIFETIME_YEARS, false, false, Collections.emptySet());
    }

    public SourceScanner(RuleRegistry ruleRegistry, int dataLifetimeYears) {
        this(ruleRegistry, dataLifetimeYears, false, false, Collections.emptySet());
    }

    public SourceScanner(boolean includeSamples) {
        this(RuleRegistry.getInstance(), RiskScoreCalculator.DEFAULT_DATA_LIFETIME_YEARS, includeSamples, false, Collections.emptySet());
    }

    public SourceScanner(RuleRegistry ruleRegistry, int dataLifetimeYears, boolean includeSamples) {
        this(ruleRegistry, dataLifetimeYears, includeSamples, false, Collections.emptySet());
    }

    public SourceScanner(RuleRegistry ruleRegistry, int dataLifetimeYears, boolean includeSamples,
                         boolean includeTests, Set<String> excludedModules) {
        this.ruleRegistry = ruleRegistry;
        this.dataLifetimeYears = dataLifetimeYears;
        this.includeSamples = includeSamples;
        this.includeTests = includeTests;
        if (excludedModules == null || excludedModules.isEmpty()) {
            this.excludedModules = Collections.emptySet();
        } else {
            Set<String> set = new HashSet<>();
            for (String m : excludedModules) {
                if (m != null && !m.trim().isEmpty()) {
                    set.add(m.trim().toLowerCase());
                }
            }
            this.excludedModules = Collections.unmodifiableSet(set);
        }
    }

    public boolean isIncludeSamples() {
        return includeSamples;
    }

    public boolean isIncludeTests() {
        return includeTests;
    }

    public Set<String> getExcludedModules() {
        return excludedModules;
    }

    public List<ScanFinding> scanDirectory(Path rootPath) throws IOException {
        List<ScanFinding> findings = new ArrayList<>();
        if (!Files.exists(rootPath)) {
            return findings;
        }

        Files.walkFileTree(rootPath, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (dir.equals(rootPath)) {
                    return FileVisitResult.CONTINUE;
                }
                if (isPathIgnored(rootPath, dir)) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (isPathIgnored(rootPath, file)) {
                    return FileVisitResult.CONTINUE;
                }
                if (attrs.isRegularFile()) {
                    if (attrs.size() > MAX_FILE_SIZE) {
                        return FileVisitResult.CONTINUE; // Skip files > 1 MB
                    }
                    String ext = getFileExtension(file);
                    if (ALLOWED_EXTENSIONS.contains(ext) && !isBinary(file)) {
                        scanFile(rootPath, file, findings);
                    }
                }
                return FileVisitResult.CONTINUE;
            }
        });

        return findings;
    }

    private boolean isPathIgnored(Path rootPath, Path path) {
        if (path.equals(rootPath)) {
            return false;
        }
        Path rel;
        try {
            rel = rootPath.relativize(path);
        } catch (IllegalArgumentException e) {
            return false;
        }

        String fileName = path.getFileName() != null ? path.getFileName().toString() : "";
        if (!includeTests && "rules.yaml".equalsIgnoreCase(fileName)) {
            return true;
        }

        String relStr = rel.toString().replace('\\', '/');
        if (!includeTests) {
            String relNorm = "/" + relStr + "/";
            if (relNorm.contains("/src/test/")) {
                return true;
            }
        }

        for (Path segment : rel) {
            String name = segment.toString();
            if (DEFAULT_IGNORED_DIRECTORIES.contains(name)) {
                return true;
            }
            if (!includeSamples && "samples".equalsIgnoreCase(name)) {
                return true;
            }
            if (excludedModules.contains(name.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public List<ScanFinding> scanSingleFile(Path rootPath, Path file) throws IOException {
        List<ScanFinding> findings = new ArrayList<>();
        if (Files.exists(file) && Files.isRegularFile(file)) {
            if (Files.size(file) <= MAX_FILE_SIZE && !isBinary(file)) {
                scanFile(rootPath, file, findings);
            }
        }
        return findings;
    }

    private void scanFile(Path rootPath, Path file, List<ScanFinding> findings) {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (Exception e) {
            try {
                lines = Files.readAllLines(file, StandardCharsets.ISO_8859_1);
            } catch (Exception ignored) {
                return; // Unreadable as text
            }
        }

        String relPath = rootPath.relativize(file).toString().replace('\\', '/');
        String ext = getFileExtension(file);

        if ("xml".equals(ext)) {
            lines = maskXmlTags(lines, Set.of("description", "name"));
        }

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            int lineNum = i + 1;

            // 1. Check Hardcoded PEM Private Key
            if (PEM_PRIVATE_KEY_PATTERN.matcher(line).find() && !line.contains("[REDACTED]")) {
                addFinding(findings, "RULE-HARDCODED-SECRET", relPath, lineNum,
                        "-----BEGIN PRIVATE KEY----- [REDACTED]", "PEM_PRIVATE_KEY", null);
                continue;
            }

            // 2. Check Hardcoded Secret Literal
            Matcher secMatcher = HARDCODED_SECRET_PATTERN.matcher(line);
            if (secMatcher.find()) {
                String secret = secMatcher.group(1);
                String redactedLine = SecretRedactor.redactSnippet(line.trim(), secret);
                addFinding(findings, "RULE-HARDCODED-SECRET", relPath, lineNum,
                        redactedLine, "HARDCODED_CREDENTIAL", null);
            }

            // 3. Scan for Weak Randomness
            if (JAVA_UTIL_RANDOM_PATTERN.matcher(line).find()) {
                // Check current and adjacent lines for security context
                String contextWindow = getContextWindow(lines, i, 2);
                if (SECURITY_CONTEXT_PATTERN.matcher(contextWindow).find()) {
                    addFinding(findings, "RULE-WEAK-RNG", relPath, lineNum,
                            line.trim(), "java.util.Random / Math.random", null);
                }
            }

            // 4. Scan for Static or Zero IV/Nonce
            if ("java".equals(ext) && STATIC_IV_PATTERN.matcher(line).find()) {
                addFinding(findings, "RULE-STATIC-IV", relPath, lineNum,
                        line.trim(), "Static/Zero IV", null);
            }

            // 5. Language-Specific Inspection
            if ("java".equals(ext)) {
                scanJavaLine(lines, i, relPath, findings);
            } else {
                scanGenericScriptOrConfigLine(line, relPath, lineNum, findings);
            }
        }
    }

    private void scanJavaLine(List<String> lines, int lineIndex, String file, List<ScanFinding> findings) {
        String line = lines.get(lineIndex);
        int lineNum = lineIndex + 1;

        Matcher jcaMatcher = JAVA_GET_INSTANCE_PATTERN.matcher(line);
        while (jcaMatcher.find()) {
            String algoLiteral = jcaMatcher.group(1).trim();
            inspectAlgorithm(lines, lineIndex, file, lineNum, line.trim(), algoLiteral, findings);
        }
    }

    private void inspectAlgorithm(List<String> lines, int lineIndex, String file, int lineNum,
                                  String snippet, String algo, List<ScanFinding> findings) {
        String upper = algo.toUpperCase();

        // 1. Positive Rule: PQC-READY
        if (upper.contains("ML-KEM") || upper.contains("ML-DSA") ||
            upper.contains("SLH-DSA") || upper.contains("FN-DSA") ||
            upper.contains("KYBER") || upper.contains("DILITHIUM")) {
            addFinding(findings, "RULE-PQC-READY", file, lineNum, snippet, algo, null);
            return;
        }

        // 2. RSA: Check key size in nearby window
        if (upper.equals("RSA") || upper.startsWith("RSA/") || upper.contains("WITHRSA")) {
            Integer keySize = findNearbyKeySize(lines, lineIndex, 4);
            if (keySize != null && keySize < 2048) {
                addFinding(findings, "RULE-RSA-WEAK", file, lineNum, snippet, "RSA-" + keySize,
                        "RSA key size " + keySize + " bits is critically weak and vulnerable to classical factoring.");
            } else {
                String label = keySize != null ? "RSA-" + keySize : "RSA";
                addFinding(findings, "RULE-RSA", file, lineNum, snippet, label, null);
            }
            if (upper.contains("SHA1") || upper.contains("MD5")) {
                inspectHashSubstrings(upper, file, lineNum, snippet, algo, findings);
            }
            return;
        }

        // 3. ECC family: ECDH, ECDSA, X25519, Ed25519, EC, secp256r1
        if (upper.contains("X25519") || upper.contains("ED25519") ||
            upper.contains("ECDH") || upper.contains("ECDSA") ||
            upper.equals("EC") || upper.contains("SECP256") || upper.contains("WITHECDSA")) {
            addFinding(findings, "RULE-ECC", file, lineNum, snippet, algo, null);
            if (upper.contains("SHA1") || upper.contains("MD5")) {
                inspectHashSubstrings(upper, file, lineNum, snippet, algo, findings);
            }
            return;
        }

        // 4. DH / DSA
        if (upper.equals("DIFFIEHELLMAN") || upper.equals("DH") || upper.equals("DSA") || upper.contains("WITHDSA")) {
            addFinding(findings, "RULE-DH-DSA", file, lineNum, snippet, algo, null);
            return;
        }

        // 5. Symmetric Ciphers: DES, 3DES, RC4, Blowfish, AES-ECB, AES-128
        if (upper.contains("DESEDE") || upper.contains("3DES") || upper.equals("DES") || upper.startsWith("DES/")) {
            addFinding(findings, "RULE-DES-3DES", file, lineNum, snippet, algo, null);
            return;
        }

        if (upper.contains("RC4") || upper.contains("ARCFOUR") || upper.contains("BLOWFISH")) {
            addFinding(findings, "RULE-RC4-BLOWFISH", file, lineNum, snippet, algo, null);
            return;
        }

        if (upper.contains("/ECB/") || upper.endsWith("/ECB")) {
            addFinding(findings, "RULE-AES-ECB", file, lineNum, snippet, algo, null);
            return;
        }

        if (upper.equals("AES") || upper.startsWith("AES/")) {
            Integer keySize = findNearbyKeySize(lines, lineIndex, 3);
            if (keySize != null && keySize == 128) {
                addFinding(findings, "RULE-AES128", file, lineNum, snippet, "AES-128", null);
            }
            return;
        }

        // 6. Hashes: MD5, SHA-1
        inspectHashSubstrings(upper, file, lineNum, snippet, algo, findings);
    }

    private void inspectHashSubstrings(String upper, String file, int lineNum, String snippet,
                                       String algo, List<ScanFinding> findings) {
        if (upper.contains("MD5")) {
            addFinding(findings, "RULE-MD5", file, lineNum, snippet, algo, null);
        } else if (upper.contains("SHA-1") || upper.contains("SHA1")) {
            addFinding(findings, "RULE-SHA1", file, lineNum, snippet, algo, null);
        }
    }

    private void scanGenericScriptOrConfigLine(String line, String file, int lineNum, List<ScanFinding> findings) {
        String upper = line.toUpperCase();
        String trimmed = line.trim();

        // PQC-READY in non-java code/config
        if (upper.contains("ML-KEM") || upper.contains("ML-DSA") ||
            upper.contains("SLH-DSA") || upper.contains("KYBER") || upper.contains("DILITHIUM")) {
            addFinding(findings, "RULE-PQC-READY", file, lineNum, trimmed, "PQC Primitive", null);
            return;
        }

        if (upper.contains("MD5") && (upper.contains("HASH") || upper.contains("DIGEST") || upper.contains("ALGORITHM"))) {
            addFinding(findings, "RULE-MD5", file, lineNum, trimmed, "MD5", null);
        } else if (upper.contains("SHA1") && (upper.contains("HASH") || upper.contains("DIGEST") || upper.contains("ALGORITHM"))) {
            addFinding(findings, "RULE-SHA1", file, lineNum, trimmed, "SHA-1", null);
        }

        if (upper.contains("DES") && (upper.contains("CIPHER") || upper.contains("ENCRYPTION") || upper.contains("ALGORITHM"))) {
            addFinding(findings, "RULE-DES-3DES", file, lineNum, trimmed, "DES", null);
        } else if (upper.contains("RC4") || upper.contains("BLOWFISH")) {
            addFinding(findings, "RULE-RC4-BLOWFISH", file, lineNum, trimmed, "RC4/Blowfish", null);
        } else if (upper.contains("AES-128") || upper.contains("AES_128")) {
            addFinding(findings, "RULE-AES128", file, lineNum, trimmed, "AES-128", null);
        }
    }

    private void addFinding(List<ScanFinding> findings, String ruleId, String file, int line,
                            String snippet, String algorithm, String customExplanation) {
        Rule rule = ruleRegistry.getRule(ruleId);
        if (rule == null) {
            return;
        }

        int score = RiskScoreCalculator.computeRiskScore(rule.category(), rule.baseScore(), dataLifetimeYears);
        String severity = RiskScoreCalculator.scoreToSeverity(score, rule.category());
        String explanation = customExplanation != null ? customExplanation : rule.explanation();

        ScanFinding finding = new ScanFinding(
                UUID.randomUUID().toString(),
                rule.id(),
                rule.category(),
                file,
                line,
                snippet,
                algorithm,
                rule.quantumVulnerable(),
                severity,
                score,
                explanation,
                rule.recommendation(),
                rule.migrationTarget()
        );
        findings.add(finding);
    }

    private Integer findNearbyKeySize(List<String> lines, int centerIndex, int radius) {
        int start = Math.max(0, centerIndex - radius);
        int end = Math.min(lines.size() - 1, centerIndex + radius);
        for (int i = start; i <= end; i++) {
            Matcher m = KEY_SIZE_PATTERN.matcher(lines.get(i));
            if (m.find()) {
                try {
                    return Integer.parseInt(m.group(1));
                } catch (NumberFormatException ignored) {}
            }
        }
        return null;
    }

    private String getContextWindow(List<String> lines, int centerIndex, int radius) {
        int start = Math.max(0, centerIndex - radius);
        int end = Math.min(lines.size() - 1, centerIndex + radius);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i <= end; i++) {
            sb.append(lines.get(i)).append(" ");
        }
        return sb.toString();
    }

    private String getFileExtension(Path file) {
        String name = file.getFileName().toString();
        int idx = name.lastIndexOf('.');
        return (idx > 0 && idx < name.length() - 1) ? name.substring(idx + 1).toLowerCase() : "";
    }

    private boolean isBinary(Path file) {
        try (InputStream is = Files.newInputStream(file)) {
            byte[] buf = new byte[8000];
            int read = is.read(buf);
            for (int i = 0; i < read; i++) {
                if (buf[i] == 0x00) {
                    return true;
                }
            }
        } catch (IOException ignored) {}
        return false;
    }

    private List<String> maskXmlTags(List<String> lines, Set<String> tagNames) {
        if (lines == null || lines.isEmpty() || tagNames == null || tagNames.isEmpty()) {
            return lines;
        }
        String fullText = String.join("\n", lines);
        String tagRegex = String.join("|", tagNames);
        Pattern p = Pattern.compile("(?is)<(" + tagRegex + ")\\b[^>]*>(.*?)</\\1>");
        Matcher m = p.matcher(fullText);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String inner = m.group(2);
            StringBuilder maskedInner = new StringBuilder(inner.length());
            for (int k = 0; k < inner.length(); k++) {
                char c = inner.charAt(k);
                maskedInner.append((c == '\n' || c == '\r') ? c : ' ');
            }
            String replacement = Matcher.quoteReplacement(
                    fullText.substring(m.start(), m.start(2)) + maskedInner + fullText.substring(m.end(2), m.end())
            );
            m.appendReplacement(sb, replacement);
        }
        m.appendTail(sb);
        return Arrays.asList(sb.toString().split("\n", -1));
    }
}
