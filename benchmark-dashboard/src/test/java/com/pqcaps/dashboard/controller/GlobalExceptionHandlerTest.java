package com.pqcaps.dashboard.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@DisplayName("Global Exception Handler Tests")
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    @DisplayName("AsyncRequestTimeoutException handler returns no body (void) and throws no exception")
    void asyncRequestTimeoutHandler_returnsNoBodyAndNoException() {
        AsyncRequestTimeoutException ex = new AsyncRequestTimeoutException();
        assertDoesNotThrow(() -> handler.handleAsyncRequestTimeout(ex));
    }

    @Test
    @DisplayName("handleGeneralException returns nothing when Accept is text/event-stream")
    void handleGeneralException_eventStreamAccept_returnsNothing() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Accept", "text/event-stream");

        ResponseEntity<Map<String, Object>> response = handler.handleGeneralException(new RuntimeException("SSE error"), request);
        assertThat(response).isNull();
    }

    @Test
    @DisplayName("handleGeneralException returns nothing when Content-Type is text/event-stream")
    void handleGeneralException_eventStreamContentType_returnsNothing() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("text/event-stream");

        ResponseEntity<Map<String, Object>> response = handler.handleGeneralException(new RuntimeException("SSE error"), request);
        assertThat(response).isNull();
    }

    @Test
    @DisplayName("handleGeneralException returns 500 JSON for standard requests")
    void handleGeneralException_standardRequest_returns500Json() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Accept", "application/json");

        ResponseEntity<Map<String, Object>> response = handler.handleGeneralException(new RuntimeException("Standard error"), request);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode().value()).isEqualTo(500);
        assertThat(response.getBody()).containsKey("error");
    }
}
