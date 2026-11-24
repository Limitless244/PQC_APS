package com.pqcaps.dashboard.benchmark;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.Security;

/**
 * Command-line entry point to execute benchmarks directly.
 * Usage: {@code BenchmarkCli [quick|full]}
 */
public final class BenchmarkCli {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public static void main(String[] args) {
        boolean quick = (args == null || args.length == 0 || !"full".equalsIgnoreCase(args[0]));
        System.out.printf(">>> Executing PQC-APS Cryptographic Benchmarks (Mode: %s)...%n", quick ? "QUICK" : "FULL");
        BenchmarkReport report = BenchmarkRunner.run(quick);
        System.out.printf(">>> Benchmark complete. Handshake wire overhead ratio: %.2fx (key material only: %.2fx)%n",
                report.summary().handshakeWireOverheadRatio(),
                report.summary().keyMaterialOverheadRatio());
    }
}
