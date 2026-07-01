package com.huawei.audit.job;

import com.huawei.audit.orchestrator.AuditOrchestrator;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Kicks off continuation for jobs AuditJobStore restored as PARTIAL on
 * startup. Wired via ApplicationReadyEvent (not constructor injection) so
 * AuditJobStore — which only reconstructs in-memory state from disk — never
 * depends on AuditOrchestrator.
 */
@Component
public class ResumeCoordinator {
    private final AuditJobStore jobStore;
    private final AuditOrchestrator orchestrator;

    public ResumeCoordinator(AuditJobStore jobStore, AuditOrchestrator orchestrator) {
        this.jobStore = jobStore;
        this.orchestrator = orchestrator;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void resumePendingJobs() {
        jobStore.jobsNeedingResume().forEach(orchestrator::resume);
    }
}
