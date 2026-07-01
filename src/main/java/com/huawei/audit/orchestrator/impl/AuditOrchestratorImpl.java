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

    @Override
    public void resume(AuditJob job) {
        // Resumed continuations skip jobSlots entirely: this job was already
        // admitted once (it reached PARTIAL before a restart), it's not new
        // intake work competing with fresh submissions, and its source is
        // already prepared on disk. Gating it on the same admission semaphore
        // as submit() would let a long multi-round continuation starve new
        // audits from ever starting after a crash.
        executor.submit(() -> runResumed(job));
    }

    private void run(AuditJob job) {
        boolean acquired = false;
        try {
            jobSlots.acquire();
            acquired = true;

            SourceWorkspaceService.PreparedSource source = sources.prepare(job);
            job.setStatus(JobStatus.RUNNING);
            // Persist job-meta.json as soon as cacheKey/projectPath are known,
            // not only at the end: if the process dies mid-round (before this
            // job ever reaches finish()/the catch block), a restart must still
            // be able to restore cacheKey/selectedInterfaceIds correctly —
            // otherwise the analysis cache key comes back empty and every
            // resume re-runs the full white-box analysis from scratch forever.
            persistMeta(job);
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
            finish(job, result);
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

    private void runResumed(AuditJob job) {
        try {
            SourceWorkspaceService.PreparedSource source = sources.prepare(job);
            job.setStatus(JobStatus.RUNNING);
            // Refresh job-meta.json immediately: it may still say "done" from
            // the completion that triggered this resume. If the process dies
            // again before finish() runs, the next restart must see "running"
            // (falls through to the PARTIAL/progress check) rather than a
            // stale "done" that would short-circuit straight past it.
            persistMeta(job);
            Map<String, Object> techProfile = techScanner.scan(source.sourceRoot());
            job.techProfile(techProfile);
            logs.publish(
                    job,
                    "tech_profile: " + objectMapper.writeValueAsString(techProfile)
            );

            List<String> candidates = scheduler.schedule(techProfile);
            logs.publish(job,
                    "[orchestrator] resumed candidate hunters: " + String.join(", ", candidates));

            IntelligentAuditGraph.AuditResult result = intelligentGraph.invokeResumed(
                    job, source.sourceRoot(), techProfile, candidates,
                    job.reviewedHunters(), job.timedOutHunters(), job.failedHunters());
            finish(job, result);
        } catch (Exception exception) {
            String error = rootCauseMessage(exception);
            // Only status/error change here — job.findings() already holds
            // whatever prior rounds accumulated and stays intact and queryable.
            job.fail(error);
            logs.publish(job, "[FATAL] " + error);
            persistMeta(job);
        } finally {
            logs.finish(job);
        }
    }

    private void finish(AuditJob job, IntelligentAuditGraph.AuditResult result) throws Exception {
        job.findings(result.finalFindings());
        job.stats(result.stats());
        job.taskSummary(result.taskSummary());

        Path output = job.workDir().resolve("findings.json");
        Files.writeString(
                output,
                objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(result.finalFindings())
        );
        if (job.status() != JobStatus.PARTIAL) {
            job.setStatus(JobStatus.DONE);
        }
        logs.publish(
                job,
                "audit completed: " + result.finalFindings().size()
                        + " findings -> " + output
        );
        persistMeta(job);
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
