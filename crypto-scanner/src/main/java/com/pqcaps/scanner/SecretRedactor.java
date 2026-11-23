package com.pqcaps.scanner;

/**
 * Secret redaction utility.
 *
 * <p>Rule: Never write a discovered secret into the report.
 * Shows the first 4 characters followed by {@code ****}.
 */
public final class SecretRedactor {

    private SecretRedactor() {}

    /**
     * Redacts a raw secret value: retains first 4 characters and masks the remainder with '****'.
     *
     * <p>Examples:
     * <ul>
     *   <li>{@code "DUMMY_SECRET_KEY_12345"} -&gt; {@code "DUMM****"}</li>
     *   <li>{@code "secret"} -&gt; {@code "secr****"}</li>
     *   <li>{@code "key"} -&gt; {@code "key****"}</li>
     * </ul>
     */
    public static String redactSecret(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "****";
        }
        int keep = Math.min(4, secret.length());
        return secret.substring(0, keep) + "****";
    }

    /**
     * Replaces all occurrences of the plaintext secret inside a snippet with its redacted equivalent.
     */
    public static String redactSnippet(String snippet, String secret) {
        if (snippet == null || secret == null || secret.isEmpty()) {
            return snippet;
        }
        String redacted = redactSecret(secret);
        return snippet.replace(secret, redacted);
    }
}
