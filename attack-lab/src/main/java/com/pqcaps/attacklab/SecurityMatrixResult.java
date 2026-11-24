package com.pqcaps.attacklab;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Result record for the Phase 4 attack prevention matrix.
 *
 * @param attack           attack classification (Downgrade, MITM, Replay, Nonce Reuse, Tampering)
 * @param mode             target configuration mode (CLASSICAL-VULNERABLE, CLASSICAL-HARDENED, HYBRID)
 * @param status           matrix cell status (SUCCEEDED, BLOCKED, or UNDETECTED for unmonitored decryption failures)
 * @param attackSucceeded  true if the attacker achieved their goal
 * @param defenceTriggered true if the guard detected and thwarted the attack
 * @param detected         true if the attack was detected by defensive telemetry
 * @param eventId          detection event UUID from EventLog (or null if unblocked)
 * @param detail           forensic explanation
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SecurityMatrixResult(
        @JsonProperty("attack") String attack,
        @JsonProperty("mode") String mode,
        @JsonProperty("status") String status,
        @JsonProperty("attackSucceeded") boolean attackSucceeded,
        @JsonProperty("defenceTriggered") boolean defenceTriggered,
        @JsonProperty("detected") boolean detected,
        @JsonProperty("eventId") String eventId,
        @JsonProperty("detail") String detail
) {

    public SecurityMatrixResult(
            String attack,
            String mode,
            String status,
            boolean attackSucceeded,
            boolean defenceTriggered,
            String eventId,
            String detail
    ) {
        this(
                attack,
                mode,
                status,
                attackSucceeded,
                defenceTriggered,
                ("Tampering".equalsIgnoreCase(attack) && "CLASSICAL-VULNERABLE".equalsIgnoreCase(mode)) ? false : defenceTriggered,
                eventId,
                detail
        );
    }

    public SecurityMatrixResult(
            String attack,
            String mode,
            boolean attackSucceeded,
            boolean defenceTriggered,
            String eventId,
            String detail
    ) {
        this(
                attack,
                mode,
                ("Tampering".equalsIgnoreCase(attack) && "CLASSICAL-VULNERABLE".equalsIgnoreCase(mode))
                        ? "UNDETECTED"
                        : (attackSucceeded ? "SUCCEEDED" : "BLOCKED"),
                ("Tampering".equalsIgnoreCase(attack) && "CLASSICAL-VULNERABLE".equalsIgnoreCase(mode))
                        ? false
                        : attackSucceeded,
                defenceTriggered,
                ("Tampering".equalsIgnoreCase(attack) && "CLASSICAL-VULNERABLE".equalsIgnoreCase(mode))
                        ? false
                        : defenceTriggered,
                eventId,
                detail
        );
    }

    public SecurityMatrixResult(String attack, String mode, boolean attackSucceeded, String eventId, String detail) {
        this(attack, mode, attackSucceeded, !attackSucceeded, eventId, detail);
    }

    public String getAttack() { return attack; }
    public String getMode() { return mode; }
    public String getStatus() {
        return status != null ? status
                : (("Tampering".equalsIgnoreCase(attack) && "CLASSICAL-VULNERABLE".equalsIgnoreCase(mode))
                ? "UNDETECTED"
                : (attackSucceeded ? "SUCCEEDED" : "BLOCKED"));
    }
    public boolean isAttackSucceeded() { return attackSucceeded; }
    public boolean isDefenceTriggered() { return defenceTriggered; }
    public boolean isDetected() { return detected; }
    public String getEventId() { return eventId; }
    public String getDetail() { return detail; }

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static void saveToJson(File file, List<SecurityMatrixResult> results) throws IOException {
        MAPPER.writeValue(file, results);
    }

    public static List<SecurityMatrixResult> loadFromJson(File file) throws IOException {
        return MAPPER.readValue(file, MAPPER.getTypeFactory().constructCollectionType(List.class, SecurityMatrixResult.class));
    }
}
