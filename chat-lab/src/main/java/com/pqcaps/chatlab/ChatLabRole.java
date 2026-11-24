package com.pqcaps.chatlab;

/**
 * Role switch for the Chat Lab application.
 */
public enum ChatLabRole {
    CLIENT(8081),
    ATTACKER(8082),
    SERVER(8083),
    ALL(8090);

    private final int defaultWebPort;

    ChatLabRole(int defaultWebPort) {
        this.defaultWebPort = defaultWebPort;
    }

    public int getDefaultWebPort() {
        return defaultWebPort;
    }

    public static ChatLabRole fromString(String role) {
        if (role == null || role.isBlank()) {
            return CLIENT;
        }
        try {
            return ChatLabRole.valueOf(role.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown role: '" + role + "'. Allowed roles: CLIENT, ATTACKER, SERVER, ALL");
        }
    }
}
