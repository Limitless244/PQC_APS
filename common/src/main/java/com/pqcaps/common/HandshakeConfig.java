package com.pqcaps.common;

/**
 * Run-time configuration switches for the handshake and secure channel.
 *
 * <p>Each flag corresponds to one intentional vulnerability in Phase 1.
 * Setting a flag to {@code false} enables the safe behaviour introduced in Phase 4.
 *
 * <p>Use the factory methods:
 * <pre>{@code
 * HandshakeConfig cfg = HandshakeConfig.vulnerable(); // Phase 1 — all vulns on
 * HandshakeConfig cfg = HandshakeConfig.safe();       // Phase 4 — all vulns off
 * HandshakeConfig cfg = HandshakeConfig.hardened();   // Phase 4 — fully hardened
 * }</pre>
 */
public final class HandshakeConfig {

    /**
     * VULN-1 — Downgrade attack.<br>
     * When {@code true}: the server signs only {xpk_c, xpk_s, nonce_c, nonce_s} and
     * omits the suite list.
     */
    private boolean skipSuiteSignature;

    /**
     * VULN-2 — Replay attack.<br>
     * When {@code true}: the receiver accepts an {@link EncryptedRecord} regardless of
     * its sequence number.
     */
    private boolean skipSequenceCheck;

    /**
     * VULN-3 — GCM nonce reuse.<br>
     * When {@code true}: the GCM nonce counter is reset to 0 on every channel
     * creation.
     */
    private boolean unsafeNonceMode;

    /**
     * VULN-4 — Man-in-the-middle attack.<br>
     * When {@code true}: the client skips verification of the server's signature.
     */
    private boolean skipKeyPinning;

    /**
     * Master hardened mode switch for Phase 4.
     */
    private boolean hardened;

    /**
     * Step 0 review requirement: FAIL CLOSED.
     * By default false (fail closed). Only if explicitly set to true can a client
     * operate without a pinned server key.
     */
    private boolean allowInsecureNoPinning;

    private HandshakeConfig(boolean skipSuiteSignature, boolean skipSequenceCheck,
                             boolean unsafeNonceMode, boolean skipKeyPinning,
                             boolean hardened, boolean allowInsecureNoPinning) {
        this.skipSuiteSignature     = skipSuiteSignature;
        this.skipSequenceCheck      = skipSequenceCheck;
        this.unsafeNonceMode        = unsafeNonceMode;
        this.skipKeyPinning         = skipKeyPinning;
        this.hardened               = hardened;
        this.allowInsecureNoPinning = allowInsecureNoPinning;
    }

    // ── Factories ────────────────────────────────────────────────────────────

    /**
     * Phase 1 defaults — all four vulnerabilities are enabled.
     * Use this for the "before" baseline and Phase 2 attack demos.
     */
    public static HandshakeConfig vulnerable() {
        return new HandshakeConfig(true, true, true, true, false, false);
    }

    /**
     * Phase 4 defaults — all vulnerabilities are disabled.
     */
    public static HandshakeConfig safe() {
        return new HandshakeConfig(false, false, false, false, true, false);
    }

    /**
     * Phase 4 hardened configuration with active attack guards enabled.
     */
    public static HandshakeConfig hardened() {
        return new HandshakeConfig(false, false, false, false, true, false);
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    public boolean isSkipSuiteSignature()     { return skipSuiteSignature; }
    public boolean isSkipSequenceCheck()      { return skipSequenceCheck;  }
    public boolean isUnsafeNonceMode()        { return unsafeNonceMode;    }
    public boolean isSkipKeyPinning()         { return skipKeyPinning;     }
    public boolean isHardened()               { return hardened;           }
    public boolean isAllowInsecureNoPinning() { return allowInsecureNoPinning; }

    // ── Fluent setters (for per-test customisation) ───────────────────────────

    public HandshakeConfig withSkipSuiteSignature(boolean v) {
        this.skipSuiteSignature = v; return this;
    }
    public HandshakeConfig withSkipSequenceCheck(boolean v) {
        this.skipSequenceCheck = v; return this;
    }
    public HandshakeConfig withUnsafeNonceMode(boolean v) {
        this.unsafeNonceMode = v; return this;
    }
    public HandshakeConfig withSkipKeyPinning(boolean v) {
        this.skipKeyPinning = v; return this;
    }
    public HandshakeConfig withHardened(boolean v) {
        this.hardened = v;
        if (v) {
            this.skipSuiteSignature = false;
            this.skipSequenceCheck  = false;
            this.unsafeNonceMode    = false;
            this.skipKeyPinning     = false;
            this.allowInsecureNoPinning = false;
        }
        return this;
    }
    public HandshakeConfig withAllowInsecureNoPinning(boolean v) {
        this.allowInsecureNoPinning = v; return this;
    }

    @Override
    public String toString() {
        return String.format(
                "HandshakeConfig[hardened=%b, skipSuiteSig=%b, skipSeq=%b, unsafeNonce=%b, skipPinning=%b, allowInsecureNoPinning=%b]",
                hardened, skipSuiteSignature, skipSequenceCheck, unsafeNonceMode, skipKeyPinning, allowInsecureNoPinning);
    }
}
