package com.pqcaps.chatlab;

import com.pqcaps.chatlab.web.ChatLabGlobalExceptionHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThat;

class ChatLabWebControllerTest {

    @Test
    @DisplayName("Verify AsyncRequestTimeoutException returns void without body")
    void testAsyncRequestTimeoutHandler() {
        ChatLabGlobalExceptionHandler handler = new ChatLabGlobalExceptionHandler();
        assertThatCode(() -> handler.handleAsyncRequestTimeout(new AsyncRequestTimeoutException()))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Verify SSE stream errors return null (no JSON response body)")
    void testSseStreamErrorReturnsNull() {
        ChatLabGlobalExceptionHandler handler = new ChatLabGlobalExceptionHandler();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Accept", "text/event-stream");

        var response = handler.handleGeneralException(new RuntimeException("SSE broken pipe"), request);
        assertThat(response).isNull();
    }
}
