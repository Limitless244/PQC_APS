package com.pqcaps.scanner;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.*;

/**
 * Probes a TLS endpoint using SSLSocket to audit TLS protocol version, cipher suite,
 * certificate public-key algorithm, key size, signature algorithm, and expiration.
 *
 * <p><b>Safety Constraint:</b> Scans are restricted to {@code localhost} and {@code 127.0.0.1}
 * unless {@code --i-own-this-target} is explicitly supplied.
 *
 * <p><b>Known Limitation:</b> JDK 21 cannot negotiate Post-Quantum hybrid key-exchange groups
 * (e.g. X25519MLKEM768); the report notes "PQ key exchange: not detectable with this JDK".
 */
public final class TlsScanner {

    private static final Set<String> LOCAL_HOSTS = Set.of(
            "localhost", "127.0.0.1", "::1", "0.0.0.0"
    );

    private final RuleRegistry ruleRegistry;
    private final int dataLifetimeYears;

    public TlsScanner() {
        this(RuleRegistry.getInstance(), RiskScoreCalculator.DEFAULT_DATA_LIFETIME_YEARS);
    }

    public TlsScanner(RuleRegistry ruleRegistry, int dataLifetimeYears) {
        this.ruleRegistry = ruleRegistry;
        this.dataLifetimeYears = dataLifetimeYears;
    }

    public List<ScanFinding> scanEndpoint(String hostAndPort, boolean iOwnThisTarget) throws Exception {
        String[] parts = hostAndPort.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid host:port specification: '" + hostAndPort + "'");
        }
        String host = parts[0].trim();
        int port = Integer.parseInt(parts[1].trim());

        // Safety verification: only localhost allowed unless --i-own-this-target is set
        if (!LOCAL_HOSTS.contains(host.toLowerCase()) && !iOwnThisTarget) {
            throw new SecurityException(
                    "Refusing to scan remote host '" + host + "' without explicit --i-own-this-target authorization flag."
            );
        }

        List<ScanFinding> findings = new ArrayList<>();
        String targetUri = "tls://" + host + ":" + port;

        // Custom TrustManager that accepts any certificate for inspection purposes
        TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAll, new java.security.SecureRandom());
        SSLSocketFactory factory = sslContext.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new InetSocketAddress(host, port), 5000);
            socket.setSoTimeout(5000);
            socket.startHandshake();

            SSLSession session = socket.getSession();
            String protocol = session.getProtocol();
            String cipherSuite = session.getCipherSuite();

            // 1. Audit Protocol Version
            if ("SSLv3".equalsIgnoreCase(protocol) || "TLSv1".equalsIgnoreCase(protocol) || "TLSv1.1".equalsIgnoreCase(protocol)) {
                addFinding(findings, "RULE-TLS-LEGACY", targetUri, 0,
                        "Protocol: " + protocol, protocol,
                        "Legacy protocol " + protocol + " is insecure and deprecated by RFC 8996.");
            }

            // 2. Audit Cipher Suite
            if (cipherSuite.contains("_RSA_WITH_")) {
                addFinding(findings, "RULE-TLS-RSA-KEX", targetUri, 0,
                        "CipherSuite: " + cipherSuite, cipherSuite, null);
            }
            if (cipherSuite.contains("MD5")) {
                addFinding(findings, "RULE-MD5", targetUri, 0,
                        "CipherSuite: " + cipherSuite, "MD5 in TLS", null);
            } else if (cipherSuite.contains("SHA") && !cipherSuite.contains("SHA256") && !cipherSuite.contains("SHA384")) {
                addFinding(findings, "RULE-SHA1", targetUri, 0,
                        "CipherSuite: " + cipherSuite, "SHA-1 in TLS", null);
            }

            // 3. Audit Server Certificate Chain
            Certificate[] certs = session.getPeerCertificates();
            if (certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                auditCertificate(x509, targetUri, findings);
            }
        }

        return findings;
    }

    private void auditCertificate(X509Certificate x509, String targetUri, List<ScanFinding> findings) {
        // Expiration check
        Date notAfter = x509.getNotAfter();
        if (notAfter.before(new Date())) {
            addFinding(findings, "RULE-TLS-EXPIRED", targetUri, 0,
                    "Certificate Expired on: " + notAfter, "Expired Certificate",
                    "Certificate expired on " + notAfter + ". Trust chain is invalid.");
        }

        // Public key algorithm and size check
        PublicKey pk = x509.getPublicKey();
        String pkAlgo = pk.getAlgorithm().toUpperCase();

        if ("RSA".equals(pkAlgo)) {
            int keyLen = (pk instanceof RSAKey rsa) ? rsa.getModulus().bitLength() : 2048;
            if (keyLen < 2048) {
                addFinding(findings, "RULE-TLS-WEAK-KEY", targetUri, 0,
                        "Certificate RSA Key Size: " + keyLen + " bits", "RSA-" + keyLen,
                        "RSA key size of " + keyLen + " bits is critically weak and factorable.");
            } else {
                addFinding(findings, "RULE-TLS-CERT-QV", targetUri, 0,
                        "Certificate Subject: " + x509.getSubjectX500Principal().getName() + " | RSA-" + keyLen,
                        "RSA-" + keyLen,
                        "Server certificate uses quantum-vulnerable RSA-" + keyLen + " public key.");
            }
        } else if ("EC".equals(pkAlgo) || "ECDSA".equals(pkAlgo)) {
            addFinding(findings, "RULE-TLS-CERT-QV", targetUri, 0,
                    "Certificate Subject: " + x509.getSubjectX500Principal().getName() + " | " + pkAlgo,
                    pkAlgo,
                    "Server certificate uses quantum-vulnerable Elliptic Curve public key.");
        }

        // Signature algorithm
        String sigAlgo = x509.getSigAlgName().toUpperCase();
        if (sigAlgo.contains("MD5")) {
            addFinding(findings, "RULE-MD5", targetUri, 0,
                    "Certificate Signature Algorithm: " + sigAlgo, sigAlgo, null);
        } else if (sigAlgo.contains("SHA1") || sigAlgo.contains("SHA-1")) {
            addFinding(findings, "RULE-SHA1", targetUri, 0,
                    "Certificate Signature Algorithm: " + sigAlgo, sigAlgo, null);
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
}
