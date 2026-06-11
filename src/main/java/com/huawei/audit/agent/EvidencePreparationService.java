package com.huawei.audit.agent;

import com.huawei.audit.domain.AuditJob;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public interface EvidencePreparationService {
    PreparationResult prepare(
            AuditJob job,
            Path sourceRoot,
            List<String> hunters
    ) throws Exception;

    record PreparationResult(
            Map<String, String> manifest,
            Map<String, Object> analysisSummary
    ) { }
}
