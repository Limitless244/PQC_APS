package com.pqcaps.kex;

import com.pqcaps.common.SessionKeys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link HybridKeySchedule}.
 *
 * <p>Validates:
 * <ul>
 *   <li>Matching inputs derive identical SessionKeys (c2s, s2c, finishedKey).</li>
 *   <li>Altering ss1 alone alters the session keys.</li>
 *   <li>Altering ss2 alone alters the session keys.</li>
 *   <li>Altering the transcript alters the session keys.</li>
 *   <li>Finished message calculation and constant-time verification.</li>
 *   <li>PQ_ONLY mode derivation (omits ss1).</li>
 * </ul>
 */
class HybridKeyScheduleTest {

    private final byte[] ss1 = "classical-x25519-secret-32-bytes".getBytes(StandardCharsets.UTF_8);
    private final byte[] ss2 = "postquantum-mlkem-secret-32-byte".getBytes(StandardCharsets.UTF_8);
    private final byte[] nonce_c = new byte[32];
    private final byte[] nonce_s = new byte[32];
    private final byte[] transcriptHash = new byte[32];

    HybridKeyScheduleTest() {
        Arrays.fill(nonce_c, (byte) 0x11);
        Arrays.fill(nonce_s, (byte) 0x22);
        Arrays.fill(transcriptHash, (byte) 0x33);
    }

    @Test
    void identicalInputsProduceIdenticalKeys() {
        SessionKeys clientKeys = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash);
        SessionKeys serverKeys = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash);

        assertThat(clientKeys.clientToServer()).isEqualTo(serverKeys.clientToServer());
        assertThat(clientKeys.serverToClient()).isEqualTo(serverKeys.serverToClient());
        assertThat(clientKeys.finishedKey()).isEqualTo(serverKeys.finishedKey());
        assertThat(clientKeys.clientToServer()).hasSize(32);
        assertThat(clientKeys.serverToClient()).hasSize(32);
        assertThat(clientKeys.finishedKey()).hasSize(32);
    }

    @Test
    void changingSs1AloneAltersAllKeys() {
        SessionKeys original = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash);

        byte[] modifiedSs1 = ss1.clone();
        modifiedSs1[0] ^= 0x01;

        SessionKeys modified = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", modifiedSs1, ss2, nonce_c, nonce_s, transcriptHash);

        assertThat(modified.clientToServer()).isNotEqualTo(original.clientToServer());
        assertThat(modified.serverToClient()).isNotEqualTo(original.serverToClient());
        assertThat(modified.finishedKey()).isNotEqualTo(original.finishedKey());
    }

    @Test
    void changingSs2AloneAltersAllKeys() {
        SessionKeys original = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash);

        byte[] modifiedSs2 = ss2.clone();
        modifiedSs2[0] ^= 0x01;

        SessionKeys modified = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, modifiedSs2, nonce_c, nonce_s, transcriptHash);

        assertThat(modified.clientToServer()).isNotEqualTo(original.clientToServer());
        assertThat(modified.serverToClient()).isNotEqualTo(original.serverToClient());
        assertThat(modified.finishedKey()).isNotEqualTo(original.finishedKey());
    }

    @Test
    void changingTranscriptAltersAllKeys() {
        SessionKeys original = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash);

        byte[] modifiedTranscript = transcriptHash.clone();
        modifiedTranscript[5] ^= (byte) 0xFF;

        SessionKeys modified = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, modifiedTranscript);

        assertThat(modified.clientToServer()).isNotEqualTo(original.clientToServer());
        assertThat(modified.serverToClient()).isNotEqualTo(original.serverToClient());
        assertThat(modified.finishedKey()).isNotEqualTo(original.finishedKey());
    }

    @Test
    void pqOnlyModeWorksWithoutClassicalSecret() {
        SessionKeys pqKeys1 = HybridKeySchedule.deriveSessionKeys(
                "PQ_ONLY", null, ss2, nonce_c, nonce_s, transcriptHash);
        SessionKeys pqKeys2 = HybridKeySchedule.deriveSessionKeys(
                "PQ_ONLY", new byte[0], ss2, nonce_c, nonce_s, transcriptHash);

        assertThat(pqKeys1.clientToServer()).isEqualTo(pqKeys2.clientToServer());
        assertThat(pqKeys1.serverToClient()).isEqualTo(pqKeys2.serverToClient());
        assertThat(pqKeys1.finishedKey()).isEqualTo(pqKeys2.finishedKey());

        // Hybrid keys must differ from PQ_ONLY keys because ikm differs
        SessionKeys hybridKeys = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash);
        assertThat(pqKeys1.clientToServer()).isNotEqualTo(hybridKeys.clientToServer());
    }

    @Test
    void finishedMessageVerification() {
        SessionKeys keys = HybridKeySchedule.deriveSessionKeys(
                "HYBRID", ss1, ss2, nonce_c, nonce_s, transcriptHash);

        byte[] finishedTag = HybridKeySchedule.computeFinished(keys.finishedKey(), transcriptHash);
        assertThat(finishedTag).hasSize(32);

        // Verification succeeds with matching key and transcript
        boolean valid = HybridKeySchedule.verifyFinished(keys.finishedKey(), transcriptHash, finishedTag);
        assertThat(valid).isTrue();

        // Verification fails if transcript changed
        byte[] tamperedTranscript = transcriptHash.clone();
        tamperedTranscript[0] ^= 0x01;
        assertThat(HybridKeySchedule.verifyFinished(keys.finishedKey(), tamperedTranscript, finishedTag)).isFalse();

        // Verification fails if finished key is wrong (e.g. from tampered ciphertext)
        byte[] wrongFinishedKey = keys.finishedKey().clone();
        wrongFinishedKey[0] ^= 0x01;
        assertThat(HybridKeySchedule.verifyFinished(wrongFinishedKey, transcriptHash, finishedTag)).isFalse();
    }
}
