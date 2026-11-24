package com.pqcaps.chatlab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HostValidatorTest {

    @Test
    @DisplayName("HostValidator accepts strictly 127.0.0.1")
    void accepts127001() {
        assertThatCode(() -> HostValidator.validateHost("127.0.0.1"))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("HostValidator refuses all other hosts (localhost, 0.0.0.0, 192.168.*, null, etc.)")
    void refusesNon127001() {
        assertThatThrownBy(() -> HostValidator.validateHost("localhost"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Host rejected: only 127.0.0.1 is permitted");

        assertThatThrownBy(() -> HostValidator.validateHost("0.0.0.0"))
                .isInstanceOf(SecurityException.class);

        assertThatThrownBy(() -> HostValidator.validateHost("192.168.1.100"))
                .isInstanceOf(SecurityException.class);

        assertThatThrownBy(() -> HostValidator.validateHost("10.0.0.1"))
                .isInstanceOf(SecurityException.class);

        assertThatThrownBy(() -> HostValidator.validateHost(null))
                .isInstanceOf(SecurityException.class);

        assertThatThrownBy(() -> HostValidator.validateHost("example.com"))
                .isInstanceOf(SecurityException.class);
    }
}
