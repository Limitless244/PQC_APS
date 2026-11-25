package com.pqcaps.scanner;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TLS Endpoint Scanner Tests")
class TlsScannerTest {

    private static SSLServerSocket testServer;
    private static int serverPort;
    private static ExecutorService executor;

    @BeforeAll
    static void startTlsServer() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1. Generate RSA-2048 keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // 2. Generate self-signed certificate
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60000);
        Date notAfter = new Date(now + 86400000L * 30);
        X500Name subject = new X500Name("CN=localhost");

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now),
                notBefore,
                notAfter,
                subject,
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);

        // 3. Setup SSLContext
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", kp.getPrivate(), "changeit".toCharArray(), new Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        testServer = (SSLServerSocket) ssf.createServerSocket(0);
        serverPort = testServer.getLocalPort();

        executor = Executors.newCachedThreadPool();
        executor.submit(() -> {
            while (!testServer.isClosed()) {
                try {
                    Socket s = testServer.accept();
                    executor.submit(() -> {
                        try {
                            s.getInputStream().read(); // Keep open for handshake
                            s.close();
                        } catch (Exception ignored) {}
                    });
                } catch (Exception ignored) {}
            }
        });
    }

    @AfterAll
    static void stopTlsServer() throws Exception {
        if (testServer != null) {
            testServer.close();
        }
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("TLS Scan detects quantum-vulnerable RSA certificate on localhost")
    void testLocalTlsScan() throws Exception {
        TlsScanner scanner = new TlsScanner();
        List<ScanFinding> findings = scanner.scanEndpoint("127.0.0.1:" + serverPort, false);

        assertThat(findings).isNotEmpty();

        // Must find RSA certificate as quantum-vulnerable
        boolean foundRsaCert = findings.stream()
                .anyMatch(f -> f.ruleId().equals("RULE-TLS-CERT-QV") && f.quantumVulnerable());
        assertThat(foundRsaCert).isTrue();
    }

    @Test
    @DisplayName("Safety Guard: Non-local host without --i-own-this-target is REFUSED")
    void testRemoteHostRefusedWithoutFlag() {
        TlsScanner scanner = new TlsScanner();

        assertThatThrownBy(() -> scanner.scanEndpoint("example.com:443", false))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Refusing to scan remote host 'example.com' without explicit --i-own-this-target authorization flag.");
    }
}
