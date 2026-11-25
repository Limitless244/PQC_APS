package com.pqcaps.chatlab;

import com.pqcaps.chatlab.service.ChatLabAttackerService;
import com.pqcaps.chatlab.service.ChatLabClientService;
import com.pqcaps.chatlab.service.ChatLabServerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Arrays;

/**
 * Main Spring Boot entry point for Chat Lab.
 * Supports running as Client (:8081), Attacker (:8082), or Server (:8083) via:
 * {@code java -jar chat-lab.jar --role=client|attacker|server}
 */
@SpringBootApplication(scanBasePackages = {"com.pqcaps.chatlab", "com.pqcaps"})
public class ChatLabApplication {

    private static final Logger log = LoggerFactory.getLogger(ChatLabApplication.class);

    public static void main(String[] args) {
        HostValidator.validateHost(HostValidator.LOCALHOST_IP);

        String roleArg = "client";
        for (String arg : args) {
            if (arg.startsWith("--role=")) {
                roleArg = arg.substring("--role=".length());
            } else if (arg.startsWith("--app.role=")) {
                roleArg = arg.substring("--app.role=".length());
            }
        }
        if (System.getProperty("role") != null) {
            roleArg = System.getProperty("role");
        }

        ChatLabRole role = ChatLabRole.fromString(roleArg);
        System.setProperty("app.role", role.name().toLowerCase());

        boolean hasServerPort = Arrays.stream(args).anyMatch(a -> a.startsWith("--server.port="))
                || System.getProperty("server.port") != null;

        java.util.List<String> argList = new java.util.ArrayList<>(Arrays.asList(args));
        if (!hasServerPort) {
            System.setProperty("server.port", String.valueOf(role.getDefaultWebPort()));
            argList.add("--server.port=" + role.getDefaultWebPort());
        }
        if (argList.stream().noneMatch(a -> a.startsWith("--app.role="))) {
            argList.add("--app.role=" + role.name().toLowerCase());
        }

        log.info("==========================================================================");
        log.info("  STARTING CHAT LAB ROLE: {} (Web Port: {})", role, System.getProperty("server.port"));
        log.info("==========================================================================");

        SpringApplication.run(ChatLabApplication.class, argList.toArray(new String[0]));
    }

    @Bean
    public ApplicationRunner roleStartupRunner(
            ChatLabServerService serverService,
            ChatLabAttackerService attackerService,
            ChatLabClientService clientService,
            @org.springframework.beans.factory.annotation.Value("${app.role:client}") String appRole) {
        return args -> {
            String roleStr = (appRole != null && !appRole.isBlank())
                    ? appRole.toLowerCase()
                    : System.getProperty("app.role", "client").toLowerCase();
            if ("all".equals(roleStr)) {
                log.info("[ChatLab Hub] Starting ALL-IN-ONE mode: Bob (TCP :9001), Mallory (TCP :9000 -> :9001), Alice (Web :8090)");
                serverService.start();
                attackerService.setTargetPort(serverService.getTcpPort());
                attackerService.start();
                clientService.setTargetPort(attackerService.getListenPort());
            } else if ("server".equals(roleStr)) {
                log.info("[ChatLab] Auto-starting TCP Server on port {}", serverService.getTcpPort());
                serverService.start();
            } else if ("attacker".equals(roleStr)) {
                log.info("[ChatLab] Auto-starting Attacker TCP Proxy on port {} -> target {}",
                        attackerService.getListenPort(), attackerService.getTargetPort());
                attackerService.start();
            } else {
                log.info("[ChatLab] Client role initialized (Web UI on :{})", System.getProperty("server.port"));
            }
        };
    }
}
