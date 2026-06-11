package com.huawei.audit.codeql;

import com.fasterxml.jackson.databind.JsonNode;
import com.huawei.audit.domain.AuditJob;
import java.nio.file.Path;
import java.util.Map;

public interface CodeqlService {
    Path ensureDatabase(
            AuditJob job,
            Path sourceRoot,
            String cacheKey
    ) throws Exception;

    Evidence collectEvidence(
            AuditJob job,
            String hunter,
            Path database
    ) throws Exception;

    record Evidence(
            Map<String, JsonNode> results,
            Map<String, String> errors
    ) {
        public boolean allFailed() {
            return results.isEmpty() && !errors.isEmpty();
        }
    }
}
