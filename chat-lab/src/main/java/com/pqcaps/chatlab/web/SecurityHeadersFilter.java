package com.pqcaps.chatlab.web;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Enforces Content-Security-Policy frame-ancestors to permit framing strictly from the Hub origin (127.0.0.1:8090),
 * and enables Cross-Origin Resource Sharing for dashboard integration.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityHeadersFilter implements Filter {

    public static final String CSP_HEADER = "Content-Security-Policy";
    public static final String CSP_POLICY = "frame-ancestors 'self' http://127.0.0.1:8090 http://127.0.0.1:8080 http://localhost:8080 http://localhost:8090;";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse httpResponse) {
            httpResponse.setHeader(CSP_HEADER, CSP_POLICY);
            httpResponse.setHeader("Access-Control-Allow-Origin", "*");
            httpResponse.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
            httpResponse.setHeader("Access-Control-Allow-Headers", "*");
        }
        if (request instanceof HttpServletRequest httpRequest && "OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_OK);
            return;
        }
        chain.doFilter(request, response);
    }
}
