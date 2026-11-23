package com.pqcaps.common;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Contract for an asymmetric Key Encapsulation Mechanism (KEM).
 *
 * <p>Unlike Diffie-Hellman ({@link KeyExchange}), which operates symmetrically
 * (both parties generate keypairs and combine their private key with the peer's public key),
 * a KEM operates asymmetrically:
 * <ol>
 *   <li>The receiver generates an ephemeral keypair {@code (sk, pk)}.</li>
 *   <li>The sender encapsulates against {@code pk}, obtaining {@code (ciphertext, sharedSecret)}.</li>
 *   <li>The sender transmits {@code ciphertext} to the receiver.</li>
 *   <li>The receiver decapsulates {@code ciphertext} using {@code sk}, recovering the identical {@code sharedSecret}.</li>
 * </ol>
 *
 * <p>In Phase 3, this interface is implemented by {@code MlKemKeyExchange} using
 * ML-KEM-768 (NIST FIPS 203 / Kyber-768).
 */
public interface KemKeyExchange {

    /**
     * Encapsulation result containing the ciphertext to transmit and the derived shared secret.
     *
     * @param ciphertext   the encapsulated key bytes to send over the wire (~1088 bytes for ML-KEM-768)
     * @param sharedSecret the 32-byte shared secret (to be zeroized after KDF derivation)
     */
    record EncapsulationResult(byte[] ciphertext, byte[] sharedSecret) {}

    /**
     * Generates a fresh ephemeral KEM keypair for the receiver.
     *
     * @return a fresh keypair; public key is sent to the peer
     */
    KeyPair generateKeyPair();

    /**
     * Encapsulates against the peer's public key to generate ciphertext and shared secret.
     *
     * @param peerPk receiver's public key
     * @return the encapsulation result containing ciphertext and shared secret
     */
    EncapsulationResult encapsulate(PublicKey peerPk);

    /**
     * Decapsulates the ciphertext using the receiver's private key.
     *
     * <p>Note: Under IND-CCA2 security (Fujisaki-Okamoto transform in ML-KEM),
     * decapsulating a corrupted or tampered ciphertext does NOT throw an exception.
     * Instead, it deterministically produces a pseudorandom secret that differs from
     * the sender's secret (implicit rejection). The mismatch is caught downstream
     * by the {@link FinishedMessage} key confirmation!
     *
     * @param sk         receiver's private key
     * @param ciphertext ciphertext received from the sender
     * @return the recovered 32-byte shared secret
     */
    byte[] decapsulate(PrivateKey sk, byte[] ciphertext);

    /**
     * Reconstructs a {@link PublicKey} from its encoded (SubjectPublicKeyInfo DER) form.
     *
     * @param encoded DER-encoded public key bytes received from the peer
     * @return the decoded public key ready for {@link #encapsulate}
     */
    PublicKey decodePublicKey(byte[] encoded);
}
