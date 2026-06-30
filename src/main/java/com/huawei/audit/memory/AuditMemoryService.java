package com.huawei.audit.memory;

import com.huawei.audit.domain.AuditJob;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public interface AuditMemoryService {
    AuditMemoryService NOOP = new AuditMemoryService() {
        @Override
        public void rememberFindings(
                AuditJob job,
                Path sourceRoot,
                Map<String, Object> techProfile,
                List<Map<String, Object>> findings
        ) {
        }

        @Override
        public List<Map<String, Object>> recallPriors(
                AuditJob job,
                String hunter,
                String teamFocus,
                List<Map<String, Object>> endpointSurface,
                List<Map<String, String>> dependencies
        ) {
            return List.of();
        }
    };

    void rememberFindings(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<Map<String, Object>> findings
    );

    List<Map<String, Object>> recallPriors(
            AuditJob job,
            String hunter,
            String teamFocus,
            List<Map<String, Object>> endpointSurface,
            List<Map<String, String>> dependencies
    );
}
