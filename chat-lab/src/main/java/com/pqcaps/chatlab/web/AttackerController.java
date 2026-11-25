package com.pqcaps.chatlab.web;

import com.pqcaps.chatlab.model.AttackerActionOutcome;
import com.pqcaps.chatlab.model.CapturedTrafficRecord;
import com.pqcaps.chatlab.service.ChatLabAttackerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST and SSE endpoints for Mallory's Attacker proxy role (:8082).
 */
@RestController
@RequestMapping("/api/attacker")
public class AttackerController {

    private final ChatLabAttackerService attackerService;
    private final ChatLabSseService sseService;

    public AttackerController(ChatLabAttackerService attackerService, ChatLabSseService sseService) {
        this.attackerService = attackerService;
        this.sseService = sseService;

        // Hook SSE listeners
        attackerService.addTrafficListener(record -> sseService.broadcastAttacker("traffic-record", record));
        attackerService.addActionListener(action -> sseService.broadcastAttacker("attacker-action", action));
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        Map<String, Object> res = new HashMap<>();
        res.put("running", attackerService.isRunning());
        res.put("listenPort", attackerService.getListenPort());
        res.put("targetPort", attackerService.getTargetPort());
        res.put("stripHybrid", attackerService.isStripHybrid());
        res.put("enableMitm", attackerService.isEnableMitm());
        res.put("dropNextRecord", attackerService.isDropNextRecord());
        res.put("paused", attackerService.isPaused());
        res.put("capturedCount", attackerService.getCapturedTraffic().size());
        res.put("traffic", attackerService.getCapturedTraffic());
        res.put("actionCount", attackerService.getActionLog().size());
        res.put("actions", attackerService.getActionLog());
        return res;
    }

    @GetMapping("/traffic")
    public List<CapturedTrafficRecord> getTraffic() {
        return attackerService.getCapturedTraffic();
    }

    @GetMapping("/actions")
    public List<AttackerActionOutcome> getActions() {
        return attackerService.getActionLog();
    }

    @PostMapping("/replay")
    public ResponseEntity<AttackerActionOutcome> replay() {
        AttackerActionOutcome outcome = attackerService.replayLastRecord();
        return ResponseEntity.ok(outcome);
    }

    @PostMapping("/flip-bit")
    public ResponseEntity<AttackerActionOutcome> flipBit() {
        AttackerActionOutcome outcome = attackerService.flipBit();
        return ResponseEntity.ok(outcome);
    }

    @PostMapping("/strip-hybrid")
    public Map<String, Object> toggleStripHybrid(@RequestBody(required = false) Map<String, Boolean> body) {
        boolean enable = (body != null && body.containsKey("enable")) ? body.get("enable") : !attackerService.isStripHybrid();
        attackerService.setStripHybrid(enable);
        return Map.of("stripHybrid", attackerService.isStripHybrid());
    }

    @PostMapping("/enable-mitm")
    public Map<String, Object> toggleMitm(@RequestBody(required = false) Map<String, Boolean> body) {
        boolean enable = (body != null && body.containsKey("enable")) ? body.get("enable") : !attackerService.isEnableMitm();
        attackerService.setEnableMitm(enable);
        return Map.of("enableMitm", attackerService.isEnableMitm());
    }

    @PostMapping("/drop-record")
    public Map<String, Object> toggleDropRecord(@RequestBody(required = false) Map<String, Boolean> body) {
        boolean drop = (body != null && body.containsKey("drop")) ? body.get("drop") : !attackerService.isDropNextRecord();
        attackerService.setDropNextRecord(drop);
        return Map.of("dropNextRecord", attackerService.isDropNextRecord());
    }

    @PostMapping("/pause")
    public Map<String, Object> togglePause(@RequestBody(required = false) Map<String, Boolean> body) {
        boolean pause = (body != null && body.containsKey("paused")) ? body.get("paused") : !attackerService.isPaused();
        attackerService.setPaused(pause);
        return Map.of("paused", attackerService.isPaused());
    }

    @PostMapping("/reset")
    public Map<String, Object> reset() {
        attackerService.reset();
        sseService.broadcastAttacker("reset", Map.of("status", "RESET"));
        return Map.of("status", "RESET");
    }

    @GetMapping("/stream")
    public SseEmitter stream() {
        return sseService.registerAttackerEmitter();
    }
}
