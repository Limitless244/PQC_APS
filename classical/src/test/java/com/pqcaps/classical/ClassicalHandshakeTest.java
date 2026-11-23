package com.pqcaps.classical;

import com.pqcaps.common.HandshakeConfig;
import com.pqcaps.common.SessionKeys;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import com.pqcaps.common.ClientHello;
import com.pqcaps.common.ServerHello;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for the classical handshake key derivation and authentication.
 *
 * <p>Tests do NOT require a network socket — they test the crypto logic directly
 * by calling the package-private static helpers.
 */
class ClassicalHandshakeTest {

    private static KeyPair SERVER_IDENTITY; // RSA-2048 long-lived identity

    @BeforeAll
    static void generateServerIdentity() {
        SERVER_IDENTITY = new RsaSigner().generateKeyPair();
    }

    // ── Key derivation symmetry ───────────────────────────────────────────────

    /**
     * Both client and server must derive identical session keys from the same
     * shared secret + nonces, even though they compute independently.
     *
     * <p>Trace:
     * <pre>
     * Client: ss = X25519(xsk_c, xpk_s)   → 32 bytes
     * Server: ss = X25519(xsk_s, xpk_c)   → same 32 bytes  (DH property)
     *
     * Both:  salt = nonce_c || nonce_s
     *        c2s  = HKDF(ss, salt, "pqcaps-classical-c2s", 32)
     *        s2c  = HKDF(ss, salt, "pqcaps-classical-s2c", 32)
     * → client.c2s == server.c2s  ✓
     * → client.s2c == server.s2c  ✓
     * </pre>
     */
    @Test
    void clientAndServer_deriveIdenticalSessionKeys() {
        X25519KeyExchange kex = new X25519KeyExchange();

        KeyPair clientKp = kex.generateKeyPair();
        KeyPair serverKp = kex.generateKeyPair();

        // X25519 DH: both sides compute the same shared secret
        byte[] ssFromClient = kex.deriveSharedSecret(clientKp.getPrivate(), serverKp.getPublic());
        byte[] ssFromServer = kex.deriveSharedSecret(serverKp.getPrivate(), clientKp.getPublic());
        assertThat(ssFromClient).as("X25519 shared secrets must match").isEqualTo(ssFromServer);

        // Both sides derive keys from the same (ss, nonces)
        byte[] nonce_c = new byte[32]; // test vector: all zeros
        byte[] nonce_s = new byte[32];
        nonce_s[0] = 1;               // differ so we can confirm direction keys differ

        SessionKeys clientKeys = ClassicalHandshake.deriveSessionKeys(ssFromClient, nonce_c, nonce_s);
        SessionKeys serverKeys = ClassicalHandshake.deriveSessionKeys(ssFromServer, nonce_c, nonce_s);

        assertThat(clientKeys.clientToServer()).as("c2s keys match").isEqualTo(serverKeys.clientToServer());
        assertThat(clientKeys.serverToClient()).as("s2c keys match").isEqualTo(serverKeys.serverToClient());
        assertThat(clientKeys.clientToServer()).as("c2s != s2c (different info labels)")
                .isNotEqualTo(clientKeys.serverToClient());

        // Zeroize test key material
        clientKeys.zeroize();
        serverKeys.zeroize();
        Arrays.fill(ssFromClient, (byte) 0);
    }

    // ── Signature verification ────────────────────────────────────────────────

    /**
     * With the correct pinned key, the server signature must verify successfully.
     */
    @Test
    void serverSignature_withCorrectKey_verifies() {
        RsaSigner signer = new RsaSigner();
        HandshakeConfig config = HandshakeConfig.safe(); // include suite list in transcript

        byte[] nonce_c = new byte[32];
        byte[] nonce_s = new byte[32];
        nonce_s[0] = 2;

        byte[] xpk_c = new byte[44]; // dummy DER
        byte[] xpk_s = new byte[44];
        xpk_s[0] = 1;

        ClientHello hello = new ClientHello(xpk_c, List.of("CLASSICAL"), nonce_c);
        ServerHello sh    = new ServerHello(xpk_s, "CLASSICAL", nonce_s, new byte[0]);

        byte[] transcript = ClassicalHandshake.buildTranscript(hello, sh, config);
        byte[] sig = signer.sign(SERVER_IDENTITY.getPrivate(), transcript);

        boolean ok = signer.verify(SERVER_IDENTITY.getPublic(), transcript, sig);
        assertThat(ok).as("Correct pinned key must verify").isTrue();
    }

    /**
     * A WRONG pinned key (different RSA keypair) must fail verification.
     * This is the MITM detection test: the attacker uses their own key.
     */
    @Test
    void serverSignature_withWrongKey_fails() {
        RsaSigner signer     = new RsaSigner();
        KeyPair   attackerKp = signer.generateKeyPair(); // attacker's key
        HandshakeConfig config = HandshakeConfig.safe();

        byte[] nonce_c = new byte[32];
        byte[] nonce_s = new byte[32];
        byte[] xpk_c   = new byte[44];
        byte[] xpk_s   = new byte[44];

        ClientHello hello = new ClientHello(xpk_c, List.of("CLASSICAL"), nonce_c);
        ServerHello sh    = new ServerHello(xpk_s, "CLASSICAL", nonce_s, new byte[0]);

        byte[] transcript = ClassicalHandshake.buildTranscript(hello, sh, config);
        // Server signs with its real key
        byte[] sig = signer.sign(SERVER_IDENTITY.getPrivate(), transcript);

        // Client verifies against WRONG (attacker's) key → must FAIL
        boolean ok = signer.verify(attackerKp.getPublic(), transcript, sig);
        assertThat(ok).as("Wrong key must NOT verify (MITM protection)").isFalse();
    }

    /**
     * VULN-1 test: when skipSuiteSignature=true, changing the suite list
     * does NOT break the signature (the downgrade attack succeeds).
     */
    @Test
    void vuln1_modifiedSuiteList_doesNotBreakSignatureWhenSkipSuiteSignatureTrue() {
        RsaSigner signer = new RsaSigner();

        // Server builds transcript WITHOUT suite list (VULN-1)
        HandshakeConfig vulnConfig = HandshakeConfig.vulnerable();
        byte[] nonce_c = new byte[32];
        byte[] nonce_s = new byte[32];
        byte[] xpk_c   = new byte[44];
        byte[] xpk_s   = new byte[44];

        ClientHello original  = new ClientHello(xpk_c, List.of("HYBRID", "CLASSICAL"), nonce_c);
        ClientHello downgraded = new ClientHello(xpk_c, List.of("CLASSICAL"), nonce_c); // attacker stripped HYBRID
        ServerHello sh        = new ServerHello(xpk_s, "CLASSICAL", nonce_s, new byte[0]);

        // Server signed the original (without suite list in transcript)
        byte[] transcript = ClassicalHandshake.buildTranscript(original, sh, vulnConfig);
        byte[] sig = signer.sign(SERVER_IDENTITY.getPrivate(), transcript);

        // Client verifies with the DOWNGRADED hello — transcript omits suite list too,
        // so the signature still passes even though the suite list was modified.
        byte[] transcriptDowngraded = ClassicalHandshake.buildTranscript(downgraded, sh, vulnConfig);
        boolean ok = signer.verify(SERVER_IDENTITY.getPublic(), transcriptDowngraded, sig);
        assertThat(ok).as("VULN-1: downgraded suite list must still pass (vuln is active)").isTrue();
    }

    /**
     * When skipSuiteSignature=false (safe mode), changing the suite list breaks the signature.
     */
    @Test
    void safeMode_modifiedSuiteList_breaksSignature() {
        RsaSigner signer = new RsaSigner();
        HandshakeConfig safeConfig = HandshakeConfig.safe();

        byte[] nonce_c = new byte[32];
        byte[] nonce_s = new byte[32];
        byte[] xpk_c   = new byte[44];
        byte[] xpk_s   = new byte[44];

        ClientHello original  = new ClientHello(xpk_c, List.of("HYBRID", "CLASSICAL"), nonce_c);
        ClientHello downgraded = new ClientHello(xpk_c, List.of("CLASSICAL"), nonce_c);
        ServerHello sh        = new ServerHello(xpk_s, "CLASSICAL", nonce_s, new byte[0]);

        byte[] transcript = ClassicalHandshake.buildTranscript(original, sh, safeConfig);
        byte[] sig = signer.sign(SERVER_IDENTITY.getPrivate(), transcript);

        byte[] transcriptDowngraded = ClassicalHandshake.buildTranscript(downgraded, sh, safeConfig);
        boolean ok = signer.verify(SERVER_IDENTITY.getPublic(), transcriptDowngraded, sig);
        assertThat(ok).as("Safe mode: downgraded suite list MUST break signature").isFalse();
    }
}
