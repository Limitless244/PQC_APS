package com.pqcaps.dashboard.benchmark;

import com.pqcaps.auth.MlDsaSignatureScheme;
import com.pqcaps.classical.RsaSigner;
import com.pqcaps.classical.X25519KeyExchange;
import com.pqcaps.kex.MlKemKeyExchange;
import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class JmhBenchmarkSuite {

    private X25519KeyExchange xKex;
    private MlKemKeyExchange kemKex;
    private MlDsaSignatureScheme dsaAuth;
    private RsaSigner rsaSigner;

    private KeyPair kemKp;
    private KeyPair dsaKp;
    private KeyPair rsaKp;

    private byte[] samplePayload;
    private byte[] rsaSig;
    private byte[] dsaSig;
    private MlKemKeyExchange.EncapsulationResult encResult;

    @Setup
    public void setup() {
        xKex = new X25519KeyExchange();
        kemKex = new MlKemKeyExchange();
        dsaAuth = new MlDsaSignatureScheme();
        rsaSigner = new RsaSigner();

        kemKp = kemKex.generateKeyPair();
        dsaKp = dsaAuth.generateKeyPair();
        rsaKp = rsaSigner.generateKeyPair();

        samplePayload = "JMH Benchmarking Signature Payload".getBytes(StandardCharsets.UTF_8);
        rsaSig = rsaSigner.sign(rsaKp.getPrivate(), samplePayload);
        dsaSig = dsaAuth.sign(dsaKp.getPrivate(), samplePayload);
        encResult = kemKex.encapsulate(kemKp.getPublic());
    }

    @Benchmark
    public KeyPair benchKeygenX25519() {
        return xKex.generateKeyPair();
    }

    @Benchmark
    public KeyPair benchKeygenMlKem768() {
        return kemKex.generateKeyPair();
    }

    @Benchmark
    public KeyPair benchKeygenMlDsa65() {
        return dsaAuth.generateKeyPair();
    }

    @Benchmark
    public MlKemKeyExchange.EncapsulationResult benchEncapsulateMlKem768() {
        return kemKex.encapsulate(kemKp.getPublic());
    }

    @Benchmark
    public byte[] benchDecapsulateMlKem768() {
        return kemKex.decapsulate(kemKp.getPrivate(), encResult.ciphertext());
    }

    @Benchmark
    public byte[] benchSignMlDsa65() {
        return dsaAuth.sign(dsaKp.getPrivate(), samplePayload);
    }

    @Benchmark
    public boolean benchVerifyMlDsa65() {
        return dsaAuth.verify(dsaKp.getPublic(), samplePayload, dsaSig);
    }

    @Benchmark
    public byte[] benchSignRsa2048() {
        return rsaSigner.sign(rsaKp.getPrivate(), samplePayload);
    }

    @Benchmark
    public boolean benchVerifyRsa2048() {
        return rsaSigner.verify(rsaKp.getPublic(), samplePayload, rsaSig);
    }
}
