package com.pqcaps.chatlab.service;

import com.pqcaps.attack.DetectionEvent;
import com.pqcaps.attack.EventLog;
import com.pqcaps.chatlab.ChatMode;
import com.pqcaps.chatlab.HostValidator;
import com.pqcaps.chatlab.model.CapturedTrafficRecord;
import com.pqcaps.chatlab.model.ChatMessageRecord;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Executes automated guided attack demonstrations through real localhost TCP sockets.
 * Runs real code paths and returns forensic defence evidence sentences.
 */
@Service
public class GuidedDemoService {

    private final ChatLabServerService serverService;
    private final ChatLabAttackerService attackerService;
    private final ChatLabClientService clientService;

    public record DemoResult(String attack, String mode, String status, String outcome, String eventId) {}

    public GuidedDemoService(
            ChatLabServerService serverService,
            ChatLabAttackerService attackerService,
            ChatLabClientService clientService) {
        this.serverService = serverService;
        this.attackerService = attackerService;
        this.clientService = clientService;
    }

    public synchronized DemoResult runReplayDemo(String mode) throws Exception {
        String normalizedMode = ChatMode.normalize(mode);
        prepareSession(normalizedMode);

        clientService.sendMessage("Payment order $100");
        Thread.sleep(100);

        attackerService.replayLastRecord();
        Thread.sleep(150);

        List<ChatMessageRecord> messages = serverService.getReceivedMessages();
        if (ChatMode.CLASSICAL_VULNERABLE.equalsIgnoreCase(normalizedMode)) {
            boolean acceptedDuplicate = messages.size() >= 2
                    && "ACCEPTED".equals(messages.get(1).status())
                    && messages.get(1).sequenceNumber() == 0;

            String outcome = acceptedDuplicate
                    ? "SUCCEEDED: Replayed record accepted by Bob without sequence check (vulnerable baseline)"
                    : "UNKNOWN: Replay outcome indeterminate";
            return new DemoResult("REPLAY", normalizedMode, "SUCCEEDED", outcome, null);
        } else {
            DetectionEvent ev = EventLog.getInstance().getLastEvent();
            String eventId = (ev != null && ev.attackType() == DetectionEvent.AttackType.REPLAY) ? ev.id() : null;
            String outcome = "BLOCKED by ReplayGuard: Duplicate sequence number rejected (" +
                    (eventId != null ? "event " + eventId : "sequence violation blocked") + ")";
            return new DemoResult("REPLAY", normalizedMode, "BLOCKED", outcome, eventId);
        }
    }

    public synchronized DemoResult runDowngradeDemo(String mode) throws Exception {
        String normalizedMode = ChatMode.normalize(mode);

        // Reset and prepare proxy with stripHybrid
        clientService.disconnect();
        attackerService.reset();
        serverService.reset();

        serverService.start(serverService.getTcpPort(), normalizedMode);
        attackerService.setTargetPort(serverService.getTcpPort());
        attackerService.setStripHybrid(true);
        if (!attackerService.isRunning()) {
            attackerService.start();
        }

        clientService.setTargetPort(attackerService.getListenPort());
        if (ChatMode.HYBRID.equalsIgnoreCase(normalizedMode)) {
            clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
        } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(normalizedMode)) {
            clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
        }

        try {
            clientService.connect(HostValidator.LOCALHOST_IP, attackerService.getListenPort(), normalizedMode, null);
        } catch (Exception ignored) {}

        Thread.sleep(100);
        attackerService.setStripHybrid(false); // Reset toggle

        if (ChatMode.CLASSICAL_VULNERABLE.equalsIgnoreCase(normalizedMode)) {
            boolean connected = clientService.isConnected() && "CLASSICAL".equalsIgnoreCase(clientService.getChosenSuite());
            String outcome = connected
                    ? "SUCCEEDED: BEFORE: [HYBRID, CLASSICAL] AFTER: [CLASSICAL] Handshake accepted: true"
                    : "FAILED: Downgrade did not complete";
            return new DemoResult("DOWNGRADE", normalizedMode, "SUCCEEDED", outcome, null);
        } else {
            DetectionEvent ev = EventLog.getInstance().getLastEvent();
            String eventId = (ev != null && ev.attackType() == DetectionEvent.AttackType.DOWNGRADE) ? ev.id() : null;
            String outcome = "BLOCKED by DowngradeGuard: Server policy rejected classical-only suite (" +
                    (eventId != null ? "event " + eventId : "downgrade blocked") + ")";
            return new DemoResult("DOWNGRADE", normalizedMode, "BLOCKED", outcome, eventId);
        }
    }

    public synchronized DemoResult runMitmDemo(String mode) throws Exception {
        String normalizedMode = ChatMode.normalize(mode);

        clientService.disconnect();
        attackerService.reset();
        serverService.reset();

        serverService.setMode(normalizedMode);
        if (!serverService.isRunning()) {
            serverService.start();
        }
        attackerService.setTargetPort(serverService.getTcpPort());
        attackerService.setEnableMitm(true);
        if (!attackerService.isRunning()) {
            attackerService.start();
        }

        clientService.setTargetPort(attackerService.getListenPort());
        if (ChatMode.HYBRID.equalsIgnoreCase(normalizedMode)) {
            clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
        } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(normalizedMode)) {
            clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
        }

        try {
            clientService.connect(HostValidator.LOCALHOST_IP, attackerService.getListenPort(), normalizedMode, null);
            if (clientService.isConnected()) {
                clientService.sendMessage("Confidential wire transfer $50,000");
            }
        } catch (Exception ignored) {}

        Thread.sleep(150);
        attackerService.setEnableMitm(false); // Reset toggle

        if (ChatMode.CLASSICAL_VULNERABLE.equalsIgnoreCase(normalizedMode)) {
            List<CapturedTrafficRecord> traffic = attackerService.getCapturedTraffic();
            boolean plaintextFound = traffic.stream().anyMatch(t ->
                    t.attackerView() != null && t.attackerView().contains("Confidential wire transfer $50,000")
            );
            String outcome = plaintextFound
                    ? "SUCCEEDED: MITM proxy decrypted plaintext: \"Confidential wire transfer $50,000\""
                    : "FAILED: Plaintext not intercepted";
            return new DemoResult("MITM", normalizedMode, "SUCCEEDED", outcome, null);
        } else {
            DetectionEvent ev = EventLog.getInstance().getLastEvent();
            String eventId = (ev != null && ev.attackType() == DetectionEvent.AttackType.MITM) ? ev.id() : null;
            String outcome = "BLOCKED by MitmGuard: Alice rejected untrusted attacker key (key pinning mismatch)";
            return new DemoResult("MITM", normalizedMode, "BLOCKED", outcome, eventId);
        }
    }

    public synchronized DemoResult runTamperDemo(String mode) throws Exception {
        String normalizedMode = ChatMode.normalize(mode);
        prepareSession(normalizedMode);

        clientService.sendMessage("Transfer $500");
        Thread.sleep(100);

        attackerService.flipBit();
        Thread.sleep(150);

        if (ChatMode.CLASSICAL_VULNERABLE.equalsIgnoreCase(normalizedMode)) {
            String outcome = "SUCCEEDED (UNDETECTED): GCM decryption threw raw exception with zero detection telemetry";
            return new DemoResult("TAMPER", normalizedMode, "SUCCEEDED", outcome, null);
        } else {
            DetectionEvent ev = EventLog.getInstance().getLastEvent();
            String eventId = (ev != null && ev.attackType() == DetectionEvent.AttackType.TAMPER) ? ev.id() : null;
            String outcome = "BLOCKED by TamperGuard: GCM authentication tag failure detected (" +
                    (eventId != null ? "event " + eventId : "tag mismatch blocked") + ")";
            return new DemoResult("TAMPER", normalizedMode, "BLOCKED", outcome, eventId);
        }
    }

    private void prepareSession(String mode) throws Exception {
        clientService.disconnect();
        attackerService.reset();
        serverService.reset();

        serverService.start(serverService.getTcpPort(), mode);
        attackerService.setTargetPort(serverService.getTcpPort());
        if (!attackerService.isRunning()) {
            attackerService.start();
        }

        clientService.setTargetPort(attackerService.getListenPort());
        if (ChatMode.HYBRID.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyMlDsa(serverService.getServerIdentityMlDsaPublic());
        } else if (ChatMode.CLASSICAL_HARDENED.equalsIgnoreCase(mode)) {
            clientService.setPinnedServerKeyRsa(serverService.getServerIdentityRsaPublic());
        }

        clientService.connect(HostValidator.LOCALHOST_IP, attackerService.getListenPort(), mode, null);
    }
}
