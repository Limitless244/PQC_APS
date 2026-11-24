package com.pqcaps.chatlab.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.*;

/**
 * Manages Server-Sent Events (SSE) connections for live UI monitoring.
 * Applies a 30-minute timeout, transmits a 15-second heartbeat comment, and broadcasts domain events.
 */
@Service
public class ChatLabSseService {

    private static final Logger log = LoggerFactory.getLogger(ChatLabSseService.class);
    private static final long SSE_TIMEOUT_MS = 30 * 60 * 1000L; // 30 minutes

    private final List<SseEmitter> clientEmitters   = new CopyOnWriteArrayList<>();
    private final List<SseEmitter> attackerEmitters = new CopyOnWriteArrayList<>();
    private final List<SseEmitter> serverEmitters   = new CopyOnWriteArrayList<>();

    private final ScheduledExecutorService heartbeatScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "chat-lab-sse-heartbeat");
        t.setDaemon(true);
        return t;
    });

    public ChatLabSseService() {
        heartbeatScheduler.scheduleAtFixedRate(this::sendHeartbeats, 15, 15, TimeUnit.SECONDS);
    }

    public SseEmitter registerClientEmitter() {
        return createEmitter(clientEmitters, "Client");
    }

    public SseEmitter registerAttackerEmitter() {
        return createEmitter(attackerEmitters, "Attacker");
    }

    public SseEmitter registerServerEmitter() {
        return createEmitter(serverEmitters, "Server");
    }

    public void broadcastClient(String eventName, Object data) {
        broadcast(clientEmitters, eventName, data);
    }

    public void broadcastAttacker(String eventName, Object data) {
        broadcast(attackerEmitters, eventName, data);
    }

    public void broadcastServer(String eventName, Object data) {
        broadcast(serverEmitters, eventName, data);
    }

    private SseEmitter createEmitter(List<SseEmitter> list, String roleName) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);
        list.add(emitter);

        emitter.onCompletion(() -> list.remove(emitter));
        emitter.onTimeout(() -> {
            log.debug("[ChatLab-SSE] {} emitter timed out after 30 min", roleName);
            list.remove(emitter);
        });
        emitter.onError(e -> list.remove(emitter));

        try {
            // Send initial ping to confirm stream open
            emitter.send(SseEmitter.event().name("init").data("CONNECTED"));
        } catch (IOException ignored) {}

        return emitter;
    }

    private void broadcast(List<SseEmitter> list, String eventName, Object data) {
        for (SseEmitter emitter : list) {
            try {
                emitter.send(SseEmitter.event().name(eventName).data(data));
            } catch (Exception e) {
                list.remove(emitter);
            }
        }
    }

    private void sendHeartbeats() {
        sendHeartbeatComment(clientEmitters);
        sendHeartbeatComment(attackerEmitters);
        sendHeartbeatComment(serverEmitters);
    }

    private void sendHeartbeatComment(List<SseEmitter> list) {
        for (SseEmitter emitter : list) {
            try {
                emitter.send(SseEmitter.event().comment("heartbeat"));
            } catch (Exception e) {
                list.remove(emitter);
            }
        }
    }
}
