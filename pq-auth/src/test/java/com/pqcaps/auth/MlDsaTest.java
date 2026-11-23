package com.pqcaps.auth;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link MlDsaSignatureScheme}.
 *
 * <p>Verifies:
 * <ul>
 *   <li>ML-DSA-65 key generation, signing, and verification.</li>
 *   <li>Invalid signatures and tampered data are rejected.</li>
 *   <li>SubjectPublicKeyInfo encoding and decoding round-trip.</li>
 *   <li>Pinned key file persistence and loading.</li>
 *   <li>Key and signature size constraints conform to NIST FIPS 204.</li>
 * </ul>
 */
class MlDsaTest {

    private final MlDsaSignatureScheme scheme = new MlDsaSignatureScheme();

    @Test
    void keygenSignVerifyRoundTrip() {
        KeyPair kp = scheme.generateKeyPair();
        assertThat(kp).isNotNull();
        assertThat(kp.getPublic()).isNotNull();
        assertThat(kp.getPrivate()).isNotNull();

        byte[] message = "Post-quantum authentication transcript 2026".getBytes(StandardCharsets.UTF_8);
        byte[] signature = scheme.sign(kp.getPrivate(), message);

        assertThat(signature).isNotNull();
        // ML-DSA-65 signature size is ~3309 bytes
        assertThat(signature.length).isGreaterThan(3000).isLessThan(3500);

        boolean valid = scheme.verify(kp.getPublic(), message, signature);
        assertThat(valid).isTrue();
    }

    @Test
    void invalidSignatureRejected() {
        KeyPair kp = scheme.generateKeyPair();
        byte[] message = "Critical handshake transcript".getBytes(StandardCharsets.UTF_8);
        byte[] signature = scheme.sign(kp.getPrivate(), message);

        // Corrupt signature (flip 1 byte)
        byte[] corruptedSig = signature.clone();
        corruptedSig[10] ^= 0x55;

        boolean valid = scheme.verify(kp.getPublic(), message, corruptedSig);
        assertThat(valid).isFalse();
    }

    @Test
    void tamperedDataRejected() {
        KeyPair kp = scheme.generateKeyPair();
        byte[] original = "Approved cipher suite: HYBRID".getBytes(StandardCharsets.UTF_8);
        byte[] tampered = "Approved cipher suite: CLASSICAL".getBytes(StandardCharsets.UTF_8);

        byte[] signature = scheme.sign(kp.getPrivate(), original);

        boolean valid = scheme.verify(kp.getPublic(), tampered, signature);
        assertThat(valid).isFalse();
    }

    @Test
    void wrongPublicKeyRejected() {
        KeyPair kp1 = scheme.generateKeyPair();
        KeyPair kp2 = scheme.generateKeyPair();
        byte[] message = "Server identity binding".getBytes(StandardCharsets.UTF_8);

        byte[] signature = scheme.sign(kp1.getPrivate(), message);

        // Verification with wrong public key must fail
        boolean valid = scheme.verify(kp2.getPublic(), message, signature);
        assertThat(valid).isFalse();
    }

    @Test
    void publicKeyEncodingRoundTrip() {
        KeyPair kp = scheme.generateKeyPair();
        byte[] encoded = kp.getPublic().getEncoded();
        assertThat(encoded).isNotNull();
        // X.509 DER encoding includes algorithm identifier + raw public key (~1976 bytes)
        assertThat(encoded.length).isGreaterThan(1900).isLessThan(2100);

        PublicKey decoded = scheme.decodePublicKey(encoded);
        assertThat(decoded).isNotNull();
        assertThat(decoded.getEncoded()).isEqualTo(encoded);

        // Verify signature with decoded public key
        byte[] message = "Test encoding round trip".getBytes(StandardCharsets.UTF_8);
        byte[] signature = scheme.sign(kp.getPrivate(), message);
        assertThat(scheme.verify(decoded, message, signature)).isTrue();
    }

    @Test
    void pinnedKeyFilePersistence(@TempDir Path tempDir) throws IOException {
        KeyPair kp = scheme.generateKeyPair();
        Path keyFile = tempDir.resolve("server_pinned.key");

        MlDsaSignatureScheme.savePinnedPublicKey(kp.getPublic(), keyFile);
        assertThat(keyFile).exists();

        PublicKey loadedKey = MlDsaSignatureScheme.loadPinnedPublicKey(keyFile);
        assertThat(loadedKey).isNotNull();
        assertThat(loadedKey.getEncoded()).isEqualTo(kp.getPublic().getEncoded());

        // Verify that signatures made with the private key verify with the loaded pinned key
        byte[] message = "Pinned identity verification".getBytes(StandardCharsets.UTF_8);
        byte[] signature = scheme.sign(kp.getPrivate(), message);
        assertThat(scheme.verify(loadedKey, message, signature)).isTrue();
    }
}
