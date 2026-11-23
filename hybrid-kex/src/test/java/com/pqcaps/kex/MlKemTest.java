package com.pqcaps.kex;

import com.pqcaps.common.KemKeyExchange.EncapsulationResult;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link MlKemKeyExchange} (ML-KEM-768 / FIPS 203).
 *
 * <p>Validates:
 * <ul>
 *   <li>Key generation, encapsulation, and decapsulation produces identical 32-byte shared secrets.</li>
 *   <li>Implicit rejection: tampered ciphertext decapsulates to a different pseudorandom secret without throwing.</li>
 *   <li>SubjectPublicKeyInfo encoding and decoding round trip.</li>
 *   <li>NIST FIPS 203 size compliance (ciphertext 1088 bytes, raw public key 1184 bytes).</li>
 * </ul>
 */
class MlKemTest {

    private final MlKemKeyExchange kem = new MlKemKeyExchange();

    @Test
    void keygenEncapDecapRoundTrip() {
        // Receiver generates ephemeral KEM keypair
        KeyPair receiverKp = kem.generateKeyPair();
        assertThat(receiverKp).isNotNull();
        assertThat(receiverKp.getPublic()).isNotNull();
        assertThat(receiverKp.getPrivate()).isNotNull();

        // Sender encapsulates against receiver's public key
        EncapsulationResult encResult = kem.encapsulate(receiverKp.getPublic());
        assertThat(encResult).isNotNull();
        byte[] ciphertext = encResult.ciphertext();
        byte[] senderSecret = encResult.sharedSecret();

        // ML-KEM-768 ciphertext is exactly 1088 bytes, shared secret is 32 bytes
        assertThat(ciphertext).hasSize(1088);
        assertThat(senderSecret).hasSize(32);

        // Receiver decapsulates using private key
        byte[] receiverSecret = kem.decapsulate(receiverKp.getPrivate(), ciphertext);
        assertThat(receiverSecret).hasSize(32);

        // Secrets must be identical
        assertThat(receiverSecret).isEqualTo(senderSecret);
    }

    @Test
    void implicitRejectionOnTamperedCiphertext() {
        KeyPair receiverKp = kem.generateKeyPair();
        EncapsulationResult encResult = kem.encapsulate(receiverKp.getPublic());
        byte[] ciphertext = encResult.ciphertext();
        byte[] originalSecret = encResult.sharedSecret();

        // Tamper with 1 byte of the ciphertext (active attacker modification)
        byte[] tamperedCiphertext = ciphertext.clone();
        tamperedCiphertext[42] ^= 0x01;

        // In IND-CCA2 ML-KEM (Fujisaki-Okamoto transform), decapsulation does NOT throw!
        // It quietly produces a pseudorandom secret derived from (sk || tampered_ct).
        byte[] decapsulatedSecret = kem.decapsulate(receiverKp.getPrivate(), tamperedCiphertext);

        assertThat(decapsulatedSecret).isNotNull();
        assertThat(decapsulatedSecret).hasSize(32);
        // But the secret MUST NOT match the sender's shared secret!
        assertThat(decapsulatedSecret).isNotEqualTo(originalSecret);
    }

    @Test
    void publicKeyEncodingRoundTrip() {
        KeyPair kp = kem.generateKeyPair();
        byte[] encoded = kp.getPublic().getEncoded();
        assertThat(encoded).isNotNull();
        // X.509 SubjectPublicKeyInfo contains header + 1184-byte raw public key (~1208 bytes)
        assertThat(encoded.length).isGreaterThan(1184).isLessThan(1300);

        PublicKey decoded = kem.decodePublicKey(encoded);
        assertThat(decoded).isNotNull();
        assertThat(decoded.getEncoded()).isEqualTo(encoded);

        // Encapsulating against decoded public key works and matches decapsulation
        EncapsulationResult encResult = kem.encapsulate(decoded);
        byte[] recoveredSecret = kem.decapsulate(kp.getPrivate(), encResult.ciphertext());
        assertThat(recoveredSecret).isEqualTo(encResult.sharedSecret());
    }
}
