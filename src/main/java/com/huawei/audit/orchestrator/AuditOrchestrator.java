package com.huawei.audit.orchestrator;

import com.huawei.audit.domain.AuditJob;

public interface AuditOrchestrator {
    void submit(AuditJob job);

    void resume(AuditJob job);
}
