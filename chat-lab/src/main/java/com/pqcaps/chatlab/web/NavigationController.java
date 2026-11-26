package com.pqcaps.chatlab.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

/**
 * Controller directing root traffic to the appropriate HTML page based on active role.
 */
@Controller
public class NavigationController {

    private final String role;
    private final int serverPort;

    public NavigationController(
            @Value("${app.role:client}") String role,
            @Value("${server.port:8081}") int serverPort) {
        this.role = role.toLowerCase();
        this.serverPort = serverPort;
    }

    @GetMapping("/")
    public String index() {
        if ("all".equalsIgnoreCase(role)) {
            return "redirect:/hub.html";
        } else if ("attacker".equalsIgnoreCase(role)) {
            return "redirect:/attacker.html";
        } else if ("server".equalsIgnoreCase(role)) {
            return "redirect:/server.html";
        } else {
            return "redirect:/client.html";
        }
    }

    @GetMapping("/api/info")
    @ResponseBody
    public Map<String, Object> info() {
        return Map.of(
                "role", role,
                "serverPort", serverPort
        );
    }
}
