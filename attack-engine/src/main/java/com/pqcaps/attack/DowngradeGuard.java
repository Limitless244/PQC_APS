package com.pqcaps.attack;

import java.util.List;

/**
 * Prevents cipher suite downgrade attacks.
 *
 * <p>VULN-1 exploitation in Phase 2 showed that omitting the suite list from the
 * server's signed transcript allows an active proxy to strip post-quantum suites
 * and force a legacy fallback.
 *
 * <p>{@code DowngradeGuard} enforces:
 * <ol>
 *   <li>Server-side policy enforcement: rejects classical suites when {@code rejectClassical=true}
 *       or below {@code minimumSuite}.</li>
 *   <li>Client-side transcript validation: verifies that the server's signed transcript
 *       contains the client's original offered suite list.</li>
 * </ol>
 */
public final class DowngradeGuard {

    private final EventLog eventLog;

    public DowngradeGuard() {
        this(EventLog.getInstance());
    }

    public DowngradeGuard(EventLog eventLog) {
        this.eventLog = eventLog;
    }

    /**
     * Server-side: validates that the requested suite complies with migration policy.
     */
    public void validateServerPolicy(
            List<String> clientOfferedSuites,
            String selectedSuite,
            boolean rejectClassical,
            String minimumSuite) {

        if (clientOfferedSuites == null || clientOfferedSuites.isEmpty()) {
            eventLog.record(
                    DetectionEvent.AttackType.DOWNGRADE,
                    DetectionEvent.Severity.HIGH,
                    "DowngradeGuard",
                    selectedSuite,
                    DetectionEvent.Action.BLOCKED,
                    "Client offered empty or null suite list"
            );
            throw new SecurityException("Handshake aborted: no cipher suites offered by client");
        }

        if (rejectClassical && "CLASSICAL".equalsIgnoreCase(selectedSuite)) {
            eventLog.record(
                    DetectionEvent.AttackType.DOWNGRADE,
                    DetectionEvent.Severity.HIGH,
                    "DowngradeGuard",
                    selectedSuite,
                    DetectionEvent.Action.BLOCKED,
                    "Client requested CLASSICAL suite while rejectClassical=true policy is active"
            );
            throw new SecurityException("Downgrade blocked: CLASSICAL suite rejected by server policy");
        }

        if (minimumSuite != null && "HYBRID".equalsIgnoreCase(minimumSuite)) {
            if ("CLASSICAL".equalsIgnoreCase(selectedSuite) || "CLASSICAL_WEAK".equalsIgnoreCase(selectedSuite)) {
                eventLog.record(
                        DetectionEvent.AttackType.DOWNGRADE,
                        DetectionEvent.Severity.HIGH,
                        "DowngradeGuard",
                        selectedSuite,
                        DetectionEvent.Action.BLOCKED,
                        "Selected suite " + selectedSuite + " is below minimum required suite " + minimumSuite
                );
                throw new SecurityException("Downgrade blocked: selected suite is below minimum policy " + minimumSuite);
            }
        }
    }

    /**
     * Client-side: validates that the suite list signed by the server matches
     * the client's original offered list.
     */
    public void validateTranscriptSuiteBinding(
            List<String> clientOfferedSuites,
            List<String> serverSignedSuites,
            String suite) {

        if (!clientOfferedSuites.equals(serverSignedSuites)) {
            eventLog.record(
                    DetectionEvent.AttackType.DOWNGRADE,
                    DetectionEvent.Severity.HIGH,
                    "DowngradeGuard",
                    suite,
                    DetectionEvent.Action.BLOCKED,
                    String.format("Suite list mismatch! Client offered: %s, Server signed: %s",
                            clientOfferedSuites, serverSignedSuites)
            );
            throw new SecurityException("Downgrade attack detected: cipher suite list was tampered in transit");
        }
    }
}
