package com.pqcaps.dashboard;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class DashboardApplication {

    static {
        // Register Bouncy Castle JCA providers for ML-KEM and ML-DSA
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(DashboardApplication.class, args);
    }
}
