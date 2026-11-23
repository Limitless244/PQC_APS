package com.pqcaps.dashboard.service;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attack.EventLog;
import com.pqcaps.attacklab.SecurityMatrixResult;
import com.pqcaps.attacklab.SecurityMatrixRunner;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class SimulatorService {

    public record AttackSimulationResponse(
            String attack,
            String mode,
            boolean attackSucceeded,
            boolean defenceTriggered,
            String eventId,
            String detail,
            String explanation,
            String triggeredDefence,
            List<String> attackerSteps,
            DetectionEvent detectionEvent
    ) {
        public String getAttack() { return attack; }
        public String getMode() { return mode; }
        public boolean isAttackSucceeded() { return attackSucceeded; }
        public boolean isDefenceTriggered() { return defenceTriggered; }
        public String getEventId() { return eventId; }
        public String getDetail() { return detail; }
        public String getExplanation() { return explanation; }
        public String getTriggeredDefence() { return triggeredDefence; }
        public List<String> getAttackerSteps() { return attackerSteps; }
        public DetectionEvent getDetectionEvent() { return detectionEvent; }
    }

    private static final Map<String, String> EXPLANATIONS = Map.of(
            "Downgrade", "An active network adversary modifies the ClientHello cipher suite list to force negotiation of an insecure or classical-only cipher suite.",
            "MITM", "An interceptor injects an unpinned public key during key exchange to intercept, inspect, and decrypt all subsequent encrypted sessions.",
            "Replay", "An attacker captures a valid encrypted record and retransmits it later to force duplicate execution without possessing cryptographic keys.",
            "Nonce Reuse", "Encrypting two messages under the exact same AES-GCM key and nonce breaks Galois counter integrity and leaks plaintext via ciphertext XOR.",
            "Tampering", "An active attacker flips bits in the ciphertext or KEM encapsulation to alter data or probe for side-channel error oracles."
    );

    private final ReentrantLock lock = new ReentrantLock();
    private final EventLog eventLog = EventLog.getInstance();
    private final SecurityMatrixRunner runner = new SecurityMatrixRunner(eventLog);

    public AttackSimulationResponse runSimulation(String attack, String mode) {
        if (!lock.tryLock()) {
            throw new IllegalStateException("An attack simulation is currently running. Please wait.");
        }
        try {
            return doRunSimulation(attack, mode);
        } finally {
            lock.unlock();
        }
    }

    private AttackSimulationResponse doRunSimulation(String attack, String mode) {
        String canonicalAttack = normalizeAttack(attack);
        String canonicalMode = normalizeMode(mode);

        int initialEventsCount = eventLog.getEvents().size();
        SecurityMatrixResult res;

        switch (canonicalAttack) {
            case "Downgrade" -> res = runner.runDowngrade(canonicalMode);
            case "MITM" -> res = runner.runMitm(canonicalMode);
            case "Replay" -> res = runner.runReplay(canonicalMode);
            case "Nonce Reuse" -> res = runner.runNonceReuse(canonicalMode);
            case "Tampering" -> res = runner.runTampering(canonicalMode);
            default -> throw new IllegalArgumentException("Unknown attack: " + attack);
        }

        DetectionEvent event = null;
        if (res.eventId() != null) {
            event = eventLog.getEvents().stream()
                    .filter(e -> e.id().equals(res.eventId()))
                    .findFirst()
                    .orElse(null);
        }
        if (event == null && eventLog.getEvents().size() > initialEventsCount) {
            event = eventLog.getLastEvent();
        }

        String triggeredDefence = res.attackSucceeded()
                ? "None (Vulnerable unmonitored baseline)"
                : (event != null ? event.component() + " (" + event.action() + ")" : "Guard Verification Check");

        List<String> attackerSteps = generateAttackerSteps(canonicalAttack, canonicalMode, res.attackSucceeded());
        String explanation = EXPLANATIONS.getOrDefault(canonicalAttack, "Cryptographic attack against protocol baseline.");

        return new AttackSimulationResponse(
                res.attack(),
                res.mode(),
                res.attackSucceeded(),
                res.defenceTriggered(),
                res.eventId(),
                res.detail(),
                explanation,
                triggeredDefence,
                attackerSteps,
                event
        );
    }

    private String normalizeAttack(String attack) {
        if (attack == null) throw new IllegalArgumentException("Attack name cannot be null");
        String trimmed = attack.trim().toLowerCase();
        return switch (trimmed) {
            case "downgrade" -> "Downgrade";
            case "mitm" -> "MITM";
            case "replay" -> "Replay";
            case "nonce reuse", "noncereuse", "nonce_reuse" -> "Nonce Reuse";
            case "tampering", "tamper" -> "Tampering";
            default -> throw new IllegalArgumentException("Invalid attack name: '" + attack + "'. Allowed: Downgrade, MITM, Replay, Nonce Reuse, Tampering");
        };
    }

    private String normalizeMode(String mode) {
        if (mode == null) throw new IllegalArgumentException("Mode cannot be null");
        String trimmed = mode.trim().toUpperCase();
        return switch (trimmed) {
            case "CLASSICAL-VULNERABLE", "CLASSICAL_VULNERABLE", "VULNERABLE" -> "CLASSICAL-VULNERABLE";
            case "CLASSICAL-HARDENED", "CLASSICAL_HARDENED", "HARDENED" -> "CLASSICAL-HARDENED";
            case "HYBRID" -> "HYBRID";
            default -> throw new IllegalArgumentException("Invalid mode: '" + mode + "'. Allowed: CLASSICAL-VULNERABLE, CLASSICAL-HARDENED, HYBRID");
        };
    }

    private List<String> generateAttackerSteps(String attack, String mode, boolean succeeded) {
        List<String> steps = new ArrayList<>();
        switch (attack) {
            case "Downgrade" -> {
                steps.add("Step 1: Intercept ClientHello advertising post-quantum cipher suites [HYBRID, CLASSICAL]");
                steps.add("Step 2: Rewrite offered cipher suites in transit to [CLASSICAL] only");
                steps.add("Step 3: Forward tampered ClientHello to server");
                steps.add(succeeded
                        ? "Outcome: Server negotiates weak suite without verifying suite list signature -> SUCCEEDED"
                        : "Outcome: Client verifies signature over transcript containing original suite list -> BLOCKED");
            }
            case "MITM" -> {
                steps.add("Step 1: Intercept client connection request to target server");
                steps.add("Step 2: Generate and substitute rogue ephemeral and identity public keys");
                steps.add("Step 3: Attempt to complete separate key exchanges with client and server");
                steps.add(succeeded
                        ? "Outcome: Client key pinning disabled, rogue key accepted -> SUCCEEDED"
                        : "Outcome: Client verifies server identity against pinned public key -> BLOCKED");
            }
            case "Replay" -> {
                steps.add("Step 1: Eavesdrop and record legitimate encrypted packet seq=0");
                steps.add("Step 2: Wait for connection to advance to seq=1");
                steps.add("Step 3: Retransmit captured packet seq=0 over the channel");
                steps.add(succeeded
                        ? "Outcome: Sequence check disabled, duplicate message accepted -> SUCCEEDED"
                        : "Outcome: ReplayGuard detects sequence mismatch -> BLOCKED");
            }
            case "Nonce Reuse" -> {
                steps.add("Step 1: Observe first message encrypted under key K and nonce N");
                steps.add("Step 2: Force or induce sender to encrypt a second distinct message under key K and nonce N");
                steps.add("Step 3: Compute C1 XOR C2 to cancel out AES-GCM keystream and recover P1 XOR P2");
                steps.add(succeeded
                        ? "Outcome: Nonce counter reset allowed -> Keystream reused -> SUCCEEDED"
                        : "Outcome: NonceManager detects duplicate nonce allocation -> BLOCKED");
            }
            case "Tampering" -> {
                steps.add("Step 1: Intercept encrypted record or KEM ciphertext in transit");
                steps.add("Step 2: Flip byte 0 in ciphertext (ct[0] ^= 0x01)");
                steps.add("Step 3: Transmit tampered payload to receiver");
                steps.add(succeeded
                        ? "Outcome: Decryption fails with unmonitored raw error (oracle risk) -> SUCCEEDED"
                        : "Outcome: TamperGuard verifies GCM authentication tag / KEM confirmation -> BLOCKED");
            }
        }
        return steps;
    }
}
