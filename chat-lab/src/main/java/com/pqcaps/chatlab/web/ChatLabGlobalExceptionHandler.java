package com.pqcaps.chatlab.web;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;

import java.util.Map;

/**
 * Central exception handler for Chat Lab.
 * Disables body writing for SSE text/event-stream timeouts and errors.
 */
@ControllerAdvice
public class ChatLabGlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ChatLabGlobalExceptionHandler.class);

    @ExceptionHandler(AsyncRequestTimeoutException.class)
    @ResponseBody
    public void handleAsyncRequestTimeout(AsyncRequestTimeoutException ex) {
        log.debug("[ChatLab] SSE connection timeout handled gracefully (no body returned)");
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<?> handleSecurityException(SecurityException ex, HttpServletRequest request) {
        if (isSseRequest(request)) {
            return null;
        }
        log.warn("[ChatLab] Security rejected: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage() != null ? ex.getMessage() : "Security error"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleIllegalArgument(IllegalArgumentException ex, HttpServletRequest request) {
        if (isSseRequest(request)) {
            return null;
        }
        log.warn("[ChatLab] Bad request: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", ex.getMessage() != null ? ex.getMessage() : "Invalid argument"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneralException(Exception ex, HttpServletRequest request) {
        if (isSseRequest(request)) {
            log.debug("[ChatLab] SSE general stream error suppressed: {}", ex.getMessage());
            return null;
        }
        log.error("[ChatLab] Internal error: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", ex.getMessage() != null ? ex.getMessage() : "Internal error"));
    }

    private boolean isSseRequest(HttpServletRequest request) {
        if (request == null) return false;
        String accept = request.getHeader("Accept");
        String contentType = request.getHeader("Content-Type");
        return (accept != null && accept.contains(MediaType.TEXT_EVENT_STREAM_VALUE))
                || (contentType != null && contentType.contains(MediaType.TEXT_EVENT_STREAM_VALUE));
    }
}
