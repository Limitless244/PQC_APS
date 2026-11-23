package com.pqcaps.scanner;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Command-line entry point for the PQC-APS Crypto Scanner.
 *
 * <p>Usage:
 * <pre>
 *   scan --path &lt;dir&gt; [--out scan-report.json] [--lifetime &lt;years&gt;] [--fail-on &lt;CRITICAL|HIGH|MEDIUM|LOW&gt;]
 *   scan --tls &lt;host:port&gt; [--i-own-this-target] [--out scan-report.json]
 * </pre>
 */
public final class CryptoScannerMain {

    public static void main(String[] args) {
        if (args == null || args.length == 0 || "-h".equals(args[0]) || "--help".equals(args[0])) {
            printHelp();
            return;
        }

        String pathArg = null;
        String tlsArg = null;
        String outArg = "scan-report.json";
        String failOnArg = null;
        boolean iOwnThisTarget = false;
        int dataLifetimeYears = RiskScoreCalculator.DEFAULT_DATA_LIFETIME_YEARS;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "scan" -> {} // subcommand keyword
                case "--path" -> { if (++i < args.length) pathArg = args[i]; }
                case "--tls" -> { if (++i < args.length) tlsArg = args[i]; }
                case "--out" -> { if (++i < args.length) outArg = args[i]; }
                case "--lifetime" -> { if (++i < args.length) dataLifetimeYears = Integer.parseInt(args[i]); }
                case "--fail-on" -> { if (++i < args.length) failOnArg = args[i].toUpperCase(); }
                case "--i-own-this-target" -> iOwnThisTarget = true;
                default -> {
                    if (pathArg == null && tlsArg == null && !arg.startsWith("-")) {
                        pathArg = arg;
                    }
                }
            }
        }

        if (pathArg == null && tlsArg == null) {
            System.err.println("Error: Specify either --path <directory> or --tls <host:port>");
            printHelp();
            System.exit(1);
        }

        try {
            List<ScanFinding> findings = new ArrayList<>();
            String targetDescription;

            if (pathArg != null) {
                targetDescription = "Directory: " + pathArg;
                SourceScanner scanner = new SourceScanner(RuleRegistry.getInstance(), dataLifetimeYears);
                findings = scanner.scanDirectory(Path.of(pathArg));
            } else {
                targetDescription = "TLS: " + tlsArg;
                TlsScanner tlsScanner = new TlsScanner(RuleRegistry.getInstance(), dataLifetimeYears);
                findings = tlsScanner.scanEndpoint(tlsArg, iOwnThisTarget);
            }

            // Sort findings by risk score descending
            findings.sort(Comparator.comparingInt(ScanFinding::riskScore).reversed());

            ScanSummary summary = RiskScoreCalculator.createSummary(findings);
            ScanReport report = new ScanReport(
                    UUID.randomUUID().toString(),
                    targetDescription,
                    Instant.now().toString(),
                    summary,
                    findings
            );

            // Print console summary
            printConsoleSummary(report);

            // Save JSON report if outArg specified
            if (outArg != null && !outArg.isBlank()) {
                File outFile = new File(outArg);
                ScanReport.saveToJson(outFile, report);
                System.out.println("[INFO] Wrote scan report to: " + outFile.getAbsolutePath());
            }

            // Check --fail-on threshold for CI
            if (failOnArg != null) {
                int thresholdRank = severityRank(failOnArg);
                boolean failed = findings.stream()
                        .anyMatch(f -> severityRank(f.severity()) >= thresholdRank);
                if (failed) {
                    System.err.printf("[FAIL] Scan failed policy check: findings found at or above %s%n", failOnArg);
                    System.exit(2);
                }
            }

        } catch (SecurityException se) {
            System.err.println("[SECURITY ERROR] " + se.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("[SCANNER ERROR] " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void printConsoleSummary(ScanReport report) {
        System.out.println("========================================================================================================================");
        System.out.println("  PQC-APS CRYPTOGRAPHIC INVENTORY SCAN REPORT");
        System.out.printf("  Target: %-30s | Findings: %-4d | Grade: %-2s | Quantum Readiness: %-5.1f%% | Overall Score: %d/100%n",
                report.target(), report.summary().totalFindings(), report.summary().grade(),
                report.summary().quantumReadiness(), report.summary().overallScore());
        System.out.println("========================================================================================================================");
        System.out.printf("%-5s | %-9s | %-16s | %-20s | %-26s | %-24s%n",
                "Risk", "Severity", "Category", "Algorithm/Pattern", "Location", "Recommendation");
        System.out.println("------+-----------+------------------+----------------------+----------------------------+-------------------------");

        if (report.findings().isEmpty()) {
            System.out.println("  (No cryptographic findings detected)");
        } else {
            for (ScanFinding f : report.findings()) {
                String loc = f.file() + (f.line() > 0 ? ":" + f.line() : "");
                if (loc.length() > 26) loc = "..." + loc.substring(loc.length() - 23);
                String algo = f.algorithm().length() > 20 ? f.algorithm().substring(0, 17) + "..." : f.algorithm();
                String rec = f.recommendation().length() > 24 ? f.recommendation().substring(0, 21) + "..." : f.recommendation();

                System.out.printf("%-5d | %-9s | %-16s | %-20s | %-26s | %-24s%n",
                        f.riskScore(), f.severity(), f.category(), algo, loc, rec);
            }
        }

        System.out.println("========================================================================================================================");
        Map<String, Integer> counts = report.summary().countsBySeverity();
        long pqcCount = report.findings().stream().filter(f -> "PQC_READY".equalsIgnoreCase(f.category())).count();

        System.out.printf("  Counts: CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d | INFO: %d (PQC-READY: %d)%n",
                counts.getOrDefault("CRITICAL", 0),
                counts.getOrDefault("HIGH", 0),
                counts.getOrDefault("MEDIUM", 0),
                counts.getOrDefault("LOW", 0),
                counts.getOrDefault("INFO", 0),
                pqcCount
        );
        System.out.printf("  OVERALL RISK GRADE: [%s] (Risk Score: %d/100) | QUANTUM READINESS: %.1f%%%n",
                report.summary().grade(), report.summary().overallScore(), report.summary().quantumReadiness());
        System.out.println("========================================================================================================================\n");
    }

    private static int severityRank(String sev) {
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0; // INFO
        };
    }

    private static void printHelp() {
        System.out.println("""
            PQC-APS Crypto Scanner CLI
            Usage:
              scan --path <directory>      Scan source code and config files
              scan --tls <host:port>       Probe TLS endpoint (--i-own-this-target required for non-localhost)
            Options:
              --out <file>                 Save JSON report (default: scan-report.json)
              --lifetime <years>           Set expected data lifetime in years (default: 10)
              --fail-on <SEVERITY>         Exit with code 2 if any finding meets/exceeds severity (CRITICAL, HIGH, MEDIUM, LOW)
              --i-own-this-target          Authorize scanning of non-local TLS target
            """);
    }
}
