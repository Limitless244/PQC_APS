package com.pqcaps.attacklab;

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
 * @param attackSucceeded  true if the attacker achieved their goal
 * @param defenceTriggered true if the guard detected and thwarted the attack
 * @param eventId          detection event UUID from EventLog (or null if unblocked)
 * @param detail           forensic explanation
 */
public record SecurityMatrixResult(
        @JsonProperty("attack") String attack,
        @JsonProperty("mode") String mode,
        @JsonProperty("attackSucceeded") boolean attackSucceeded,
        @JsonProperty("defenceTriggered") boolean defenceTriggered,
        @JsonProperty("eventId") String eventId,
        @JsonProperty("detail") String detail
) {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static void saveToJson(File file, List<SecurityMatrixResult> results) throws IOException {
        MAPPER.writeValue(file, results);
    }

    public static List<SecurityMatrixResult> loadFromJson(File file) throws IOException {
        return MAPPER.readValue(file, MAPPER.getTypeFactory().constructCollectionType(List.class, SecurityMatrixResult.class));
    }
}
