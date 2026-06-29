package com.huawei.audit.orchestrator.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import com.huawei.audit.hunter.HunterScheduler;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.orchestrator.AuditOrchestrator;
import com.huawei.audit.orchestrator.IntelligentAuditGraph;
import com.huawei.audit.orchestrator.TechProfileScanner;
import com.huawei.audit.source.SourceWorkspaceService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import org.springframework.stereotype.Service;

@Service
public class AuditOrchestratorImpl implements AuditOrchestrator {
    private final ExecutorService executor;
    private final SourceWorkspaceService sources;
    private final TechProfileScanner techScanner;
    private final HunterScheduler scheduler;
    private final IntelligentAuditGraph intelligentGraph;
    private final JobLogBroker logs;
    private final ObjectMapper objectMapper;
    private final Semaphore jobSlots;
    private final boolean intelligentOrchestratorEnabled;

    public AuditOrchestratorImpl(
            ExecutorService executor,
            SourceWorkspaceService sources,
            TechProfileScanner techScanner,
            HunterScheduler scheduler,
            IntelligentAuditGraph intelligentGraph,
            JobLogBroker logs,
            ObjectMapper objectMapper,
            AuditProperties properties,
            OrchestratorProperties orchestratorProperties
    ) {
        this.executor = executor;
        this.sources = sources;
        this.techScanner = techScanner;
        this.scheduler = scheduler;
        this.intelligentGraph = intelligentGraph;
        this.logs = logs;
        this.objectMapper = objectMapper;
        this.jobSlots = new Semaphore(properties.maxConcurrentJobs());
        this.intelligentOrchestratorEnabled = orchestratorProperties.enabled();
    }

    @Override
    public void submit(AuditJob job) {
        executor.submit(() -> run(job));
    }

    private void run(AuditJob job) {
        boolean acquired = false;
        try {
            jobSlots.acquire();
            acquired = true;

            SourceWorkspaceService.PreparedSource source = sources.prepare(job);
            job.setStatus(JobStatus.RUNNING);
            Map<String, Object> techProfile = techScanner.scan(source.sourceRoot());
            job.techProfile(techProfile);
            logs.publish(
                    job,
                    "tech_profile: " + objectMapper.writeValueAsString(techProfile)
            );

            List<String> candidates = scheduler.schedule(techProfile);
            logs.publish(job,
                    "[orchestrator] candidate hunters: " + String.join(", ", candidates));
            logs.publish(job,
                    "[orchestrator] intelligent selection "
                            + (intelligentOrchestratorEnabled ? "enabled" : "disabled"));

            IntelligentAuditGraph.AuditResult result = intelligentGraph.invoke(
                    job, source.sourceRoot(), techProfile, candidates);
            job.findings(result.finalFindings());
            job.stats(result.stats());
            job.taskSummary(result.taskSummary());

            Path output = job.workDir().resolve("findings.json");
            Files.writeString(
                    output,
                    objectMapper.writerWithDefaultPrettyPrinter()
                            .writeValueAsString(result.finalFindings())
            );
            job.setStatus(JobStatus.DONE);
            logs.publish(
                    job,
                    "audit completed: " + result.finalFindings().size()
                            + " findings -> " + output
            );
            persistMeta(job);
        } catch (Exception exception) {
            String error = rootCauseMessage(exception);
            job.fail(error);
            logs.publish(job, "[FATAL] " + error);
            persistMeta(job);
        } finally {
            if (acquired) {
                jobSlots.release();
            }
            logs.finish(job);
        }
    }

    private void persistMeta(AuditJob job) {
        try {
            if (job.workDir() != null) {
                Files.writeString(
                        job.workDir().resolve("job-meta.json"),
                        objectMapper.writerWithDefaultPrettyPrinter()
                                .writeValueAsString(job.toMeta())
                );
            }
        } catch (Exception ignored) {
        }
    }

    private String rootCauseMessage(Exception exception) {
        Throwable cursor = exception;
        while (cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        String message = cursor.getMessage();
        if (message == null || message.isBlank()) {
            message = cursor.getClass().getName();
        }
        String topMessage = exception.getMessage();
        if (topMessage == null || topMessage.isBlank()) {
            topMessage = exception.getClass().getName();
        }
        return cursor == exception
                ? message
                : topMessage + " | root cause: "
                        + cursor.getClass().getSimpleName() + ": " + message;
    }
}
