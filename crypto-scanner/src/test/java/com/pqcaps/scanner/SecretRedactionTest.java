package com.pqcaps.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Secret Redaction Tests")
class SecretRedactionTest {

    @Test
    @DisplayName("Never leak secret: retains first 4 chars and appends ****")
    void testRedactSecret() {
        assertThat(SecretRedactor.redactSecret("DUMMY_SECRET_KEY_1234567890"))
                .isEqualTo("DUMM****");

        assertThat(SecretRedactor.redactSecret("password123"))
                .isEqualTo("pass****");

        assertThat(SecretRedactor.redactSecret("key"))
                .isEqualTo("key****");

        assertThat(SecretRedactor.redactSecret(null))
                .isEqualTo("****");
    }

    @Test
    @DisplayName("Redact snippet replaces secret occurrence")
    void testRedactSnippet() {
        String snippet = "String apiKey = \"DUMMY_SECRET_KEY_1234567890\";";
        String redacted = SecretRedactor.redactSnippet(snippet, "DUMMY_SECRET_KEY_1234567890");

        assertThat(redacted).doesNotContain("DUMMY_SECRET_KEY_1234567890");
        assertThat(redacted).contains("DUMM****");
    }
}
