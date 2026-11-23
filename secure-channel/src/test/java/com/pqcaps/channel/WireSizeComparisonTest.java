package com.pqcaps.channel;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.ClassicalCryptoSuite;
import com.pqcaps.classical.X25519KeyExchange;
import com.pqcaps.common.ClientHello;
import com.pqcaps.common.FinishedMessage;
import com.pqcaps.common.ServerHello;
import com.pqcaps.kex.MlKemKeyExchange;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Calculates and verifies exact wire sizes for CLASSICAL, HYBRID, and PQ_ONLY suites.
 * Accounts for mutual key confirmation (Finished sent by both Client and Server).
 */
class WireSizeComparisonTest {

    @Test
    void measureAndCompareWireSizes() throws Exception {
        // --- CLASSICAL ---
        X25519KeyExchange classicalKex = new X25519KeyExchange();
        KeyPair classicalKp = classicalKex.generateKeyPair();
        KeyPair rsaKp = ClassicalCryptoSuite.getInstance().signatureScheme().generateKeyPair();

        byte[] rsaSig = ClassicalCryptoSuite.getInstance().signatureScheme().sign(rsaKp.getPrivate(), new byte[32]);
        ClientHello classicalCh = new ClientHello(classicalKp.getPublic().getEncoded(), List.of("CLASSICAL"), new byte[32]);
        ServerHello classicalSh = new ServerHello(classicalKp.getPublic().getEncoded(), "CLASSICAL", new byte[32], rsaSig);

        int classicalChBytes = serialize(classicalCh).length;
        int classicalShBytes = serialize(classicalSh).length;
        int classicalTotal = classicalChBytes + classicalShBytes;

        // --- HYBRID ---
        MlKemKeyExchange kem = new MlKemKeyExchange();
        MlDsaSignatureScheme dsa = new MlDsaSignatureScheme();
        KeyPair kemKp = kem.generateKeyPair();
        KeyPair dsaKp = dsa.generateKeyPair();

        var encResult = kem.encapsulate(kemKp.getPublic());
        byte[] dsaSig = dsa.sign(dsaKp.getPrivate(), new byte[32]);

        ClientHello hybridCh = new ClientHello(
                classicalKp.getPublic().getEncoded(),
                kemKp.getPublic().getEncoded(),
                List.of("HYBRID"),
                new byte[32]);
        ServerHello hybridSh = new ServerHello(
                classicalKp.getPublic().getEncoded(),
                encResult.ciphertext(),
                "HYBRID",
                new byte[32],
                dsaSig);
        FinishedMessage hybridClientFin = new FinishedMessage(new byte[32]);
        FinishedMessage hybridServerFin = new FinishedMessage(new byte[32]);

        int hybridChBytes = serialize(hybridCh).length;
        int hybridShBytes = serialize(hybridSh).length;
        // Mutual key confirmation: 2 Finished messages (Client + Server)
        int hybridFinBytes = serialize(hybridClientFin).length + serialize(hybridServerFin).length;
        int hybridTotal = hybridChBytes + hybridShBytes + hybridFinBytes;

        // --- PQ_ONLY ---
        ClientHello pqCh = new ClientHello(
                null,
                kemKp.getPublic().getEncoded(),
                List.of("PQ_ONLY"),
                new byte[32]);
        ServerHello pqSh = new ServerHello(
                null,
                encResult.ciphertext(),
                "PQ_ONLY",
                new byte[32],
                dsaSig);
        FinishedMessage pqClientFin = new FinishedMessage(new byte[32]);
        FinishedMessage pqServerFin = new FinishedMessage(new byte[32]);

        int pqChBytes = serialize(pqCh).length;
        int pqShBytes = serialize(pqSh).length;
        int pqFinBytes = serialize(pqClientFin).length + serialize(pqServerFin).length;
        int pqTotal = pqChBytes + pqShBytes + pqFinBytes;

        System.out.println("\n==========================================================================");
        System.out.println("           WIRE SIZE COMPARISON (Handshake Messages)");
        System.out.println("==========================================================================");
        System.out.printf("%-12s | %-12s | %-12s | %-12s | %-15s%n", "Suite", "ClientHello", "ServerHello", "Finished (2)", "Total Handshake");
        System.out.println("-------------+--------------+--------------+--------------+-----------------");
        System.out.printf("%-12s | %-12s | %-12s | %-12s | %-15s%n", "CLASSICAL", classicalChBytes + " B", classicalShBytes + " B", "N/A", classicalTotal + " B");
        System.out.printf("%-12s | %-12s | %-12s | %-12s | %-15s%n", "HYBRID", hybridChBytes + " B", hybridShBytes + " B", hybridFinBytes + " B", hybridTotal + " B");
        System.out.printf("%-12s | %-12s | %-12s | %-12s | %-15s%n", "PQ_ONLY", pqChBytes + " B", pqShBytes + " B", pqFinBytes + " B", pqTotal + " B");
        System.out.println("==========================================================================\n");

        assertThat(hybridTotal).isGreaterThan(classicalTotal);
        assertThat(pqTotal).isLessThan(hybridTotal);
    }

    private static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
        }
        return baos.toByteArray();
    }
}
