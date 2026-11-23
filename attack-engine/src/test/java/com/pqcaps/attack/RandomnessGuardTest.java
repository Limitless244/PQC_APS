package com.pqcaps.attack;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RandomnessGuardTest {

    private EventLog eventLog;
    private RandomnessGuard guard;

    @BeforeEach
    void setUp() {
        eventLog = EventLog.getInstance();
        eventLog.clear();
        guard = new RandomnessGuard(eventLog);
    }

    @Test
    void providesStrongSecureRandom() {
        SecureRandom rng = RandomnessGuard.getSecureRandom();
        assertThat(rng).isNotNull();

        byte[] bytes1 = new byte[32];
        byte[] bytes2 = new byte[32];
        rng.nextBytes(bytes1);
        rng.nextBytes(bytes2);

        assertThat(bytes1).isNotEqualTo(bytes2);
    }

    @Test
    void scanProjectSourcesEnsuresNoWeakRandomInProductionCode() throws IOException {
        Path projectRoot = Path.of("..").toAbsolutePath().normalize();
        // Scan main source directories across modules
        List<String> violations = guard.scanSourceDirectory(projectRoot.resolve("common/src/main"));
        violations.addAll(guard.scanSourceDirectory(projectRoot.resolve("classical/src/main")));
        violations.addAll(guard.scanSourceDirectory(projectRoot.resolve("hybrid-kex/src/main")));
        violations.addAll(guard.scanSourceDirectory(projectRoot.resolve("pq-auth/src/main")));
        violations.addAll(guard.scanSourceDirectory(projectRoot.resolve("secure-channel/src/main")));
        violations.addAll(guard.scanSourceDirectory(projectRoot.resolve("attack-engine/src/main")));

        // Zero weak random usages allowed in production cryptographic source files!
        assertThat(violations)
                .withFailMessage("Found insecure java.util.Random or Math.random in production crypto: " + violations)
                .isEmpty();
    }
}
