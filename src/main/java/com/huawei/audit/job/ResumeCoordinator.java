package com.huawei.audit.job;

import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.orchestrator.AuditOrchestrator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class ResumeCoordinator {
    private final AuditJobStore jobStore;
    private final AuditOrchestrator orchestrator;
    private final boolean resumeOnStartup;

    @Autowired
    public ResumeCoordinator(
            AuditJobStore jobStore,
            AuditOrchestrator orchestrator,
            AuditProperties properties
    ) {
        this.jobStore = jobStore;
        this.orchestrator = orchestrator;
        this.resumeOnStartup = properties.resumeOnStartup();
    }

    ResumeCoordinator(AuditJobStore jobStore, AuditOrchestrator orchestrator) {
        this.jobStore = jobStore;
        this.orchestrator = orchestrator;
        this.resumeOnStartup = false;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void resumePendingJobs() {
        if (!resumeOnStartup) {
            return;
        }
        jobStore.jobsNeedingResume().forEach(orchestrator::resume);
    }
}
