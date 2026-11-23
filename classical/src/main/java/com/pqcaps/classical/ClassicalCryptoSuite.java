package com.pqcaps.classical;

import com.pqcaps.common.AeadCipher;
import com.pqcaps.common.CryptoSuite;
import com.pqcaps.common.KeyExchange;
import com.pqcaps.common.SignatureScheme;

/**
 * Classical cipher suite bundling X25519 + RSA-2048 + AES-256-GCM.
 *
 * <p>All three components are stateless singletons; crypto state lives in the
 * calling handshake or channel, not here.
 *
 * <p>This suite is intentionally weak against quantum attackers (it is the "before"
 * picture). The scanner in Phase 5 will flag RSA-2048 as below the NIST 3072-bit
 * recommendation.
 */
public final class ClassicalCryptoSuite implements CryptoSuite {

    private static final ClassicalCryptoSuite INSTANCE = new ClassicalCryptoSuite();

    private final X25519KeyExchange  kex    = new X25519KeyExchange();
    private final RsaSigner          signer = new RsaSigner();
    private final AesGcmCipher       cipher = new AesGcmCipher();

    private ClassicalCryptoSuite() {}

    /** Returns the singleton instance. */
    public static ClassicalCryptoSuite getInstance() { return INSTANCE; }

    @Override public String          id()               { return "CLASSICAL"; }
    @Override public KeyExchange      keyExchange()       { return kex;         }
    @Override public SignatureScheme  signatureScheme()   { return signer;       }
    @Override public AeadCipher       aeadCipher()        { return cipher;       }
}
