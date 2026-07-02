package com.huawei.audit.job;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.orchestrator.AuditOrchestrator;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class ResumeCoordinatorTest {

    @Test
    void skipsResumeByDefault() {
        AuditJobStore store = mock(AuditJobStore.class);
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        AuditJob job = new AuditJob("resume1", "java");
        when(store.jobsNeedingResume()).thenReturn(List.of(job));

        new ResumeCoordinator(store, orchestrator).resumePendingJobs();

        verify(orchestrator, never()).resume(any());
    }

    @Test
    void resumesEveryJobReturnedByTheStoreWhenEnabled() {
        AuditJobStore store = mock(AuditJobStore.class);
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        AuditJob first = new AuditJob("resume1", "java");
        AuditJob second = new AuditJob("resume2", "java");
        when(store.jobsNeedingResume()).thenReturn(List.of(first, second));

        new ResumeCoordinator(
                store,
                orchestrator,
                properties(true)
        ).resumePendingJobs();

        verify(orchestrator).resume(first);
        verify(orchestrator).resume(second);
    }

    @Test
    void doesNothingWhenNoJobsNeedResuming() {
        AuditJobStore store = mock(AuditJobStore.class);
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        when(store.jobsNeedingResume()).thenReturn(List.of());

        new ResumeCoordinator(
                store,
                orchestrator,
                properties(true)
        ).resumePendingJobs();

        verify(orchestrator, never()).resume(any());
    }

    private AuditProperties properties(boolean resumeOnStartup) {
        return new AuditProperties(
                Path.of("workspace"),
                "",
                "",
                null,
                2,
                15,
                null,
                resumeOnStartup
        );
    }
}
