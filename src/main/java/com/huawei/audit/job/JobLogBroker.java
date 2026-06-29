package com.huawei.audit.job;

import com.huawei.audit.domain.AuditJob;
import java.io.IOException;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Component
public class JobLogBroker {
    private static final Logger LOGGER = LoggerFactory.getLogger(
            JobLogBroker.class
    );

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss");

    private final ConcurrentHashMap<String, CopyOnWriteArrayList<SseEmitter>> subscribers =
            new ConcurrentHashMap<>();

    public void publish(AuditJob job, String line) {
        String stamped = "[" + LocalTime.now().format(TIME_FMT) + "] " + line;
        job.appendLog(stamped);
        writeBackendLog(job.jobId(), line);
        for (SseEmitter emitter : subscribers(job.jobId())) {
            send(emitter, stamped);
        }
    }

    public SseEmitter subscribe(AuditJob job) {
        SseEmitter emitter = new SseEmitter(0L);
        for (String line : job.logHistory()) {
            send(emitter, line);
        }
        if (job.logDone()) {
            complete(emitter);
            return emitter;
        }

        subscribers(job.jobId()).add(emitter);
        Runnable cleanup = () -> subscribers(job.jobId()).remove(emitter);
        emitter.onCompletion(cleanup);
        emitter.onTimeout(cleanup);
        emitter.onError(ignored -> cleanup.run());
        return emitter;
    }

    public void finish(AuditJob job) {
        job.logDone(true);
        List<SseEmitter> emitters = List.copyOf(subscribers(job.jobId()));
        emitters.forEach(this::complete);
        subscribers.remove(job.jobId());
    }

    private CopyOnWriteArrayList<SseEmitter> subscribers(String jobId) {
        return subscribers.computeIfAbsent(jobId, ignored -> new CopyOnWriteArrayList<>());
    }

    private void writeBackendLog(String jobId, String line) {
        String normalized = line.replace("\r", "").replace("\n", " | ");
        if (normalized.contains("[FATAL]")
                || normalized.contains("[ERROR]")
                || normalized.startsWith("ERROR")) {
            LOGGER.error("[audit:{}] {}", jobId, normalized);
        } else if (normalized.contains("[WARN]")
                || normalized.startsWith("WARN")) {
            LOGGER.warn("[audit:{}] {}", jobId, normalized);
        } else {
            LOGGER.info("[audit:{}] {}", jobId, normalized);
        }
    }

    private void send(SseEmitter emitter, String line) {
        try {
            emitter.send(SseEmitter.event().data(line.replace("\n", "\\n")));
        } catch (IOException | IllegalStateException exception) {
            emitter.completeWithError(exception);
        }
    }

    private void complete(SseEmitter emitter) {
        try {
            emitter.send(SseEmitter.event().data("[DONE]"));
            emitter.complete();
        } catch (IOException | IllegalStateException exception) {
            emitter.completeWithError(exception);
        }
    }
}
