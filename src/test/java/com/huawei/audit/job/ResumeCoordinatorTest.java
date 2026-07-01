package com.huawei.audit.job;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.orchestrator.AuditOrchestrator;
import java.util.List;
import org.junit.jupiter.api.Test;

class ResumeCoordinatorTest {

    @Test
    void resumesEveryJobReturnedByTheStore() {
        AuditJobStore store = mock(AuditJobStore.class);
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        AuditJob first = new AuditJob("resume1", "java");
        AuditJob second = new AuditJob("resume2", "java");
        when(store.jobsNeedingResume()).thenReturn(List.of(first, second));

        new ResumeCoordinator(store, orchestrator).resumePendingJobs();

        verify(orchestrator).resume(first);
        verify(orchestrator).resume(second);
    }

    @Test
    void doesNothingWhenNoJobsNeedResuming() {
        AuditJobStore store = mock(AuditJobStore.class);
        AuditOrchestrator orchestrator = mock(AuditOrchestrator.class);
        when(store.jobsNeedingResume()).thenReturn(List.of());

        new ResumeCoordinator(store, orchestrator).resumePendingJobs();

        verify(orchestrator, never()).resume(any());
    }
}
