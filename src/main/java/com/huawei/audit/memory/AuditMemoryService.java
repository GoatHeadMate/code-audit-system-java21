package com.huawei.audit.memory;

import com.huawei.audit.domain.AuditJob;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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

    default void rememberFeedback(
            AuditJob job,
            int findingIndex,
            Map<String, Object> finding,
            String verdict,
            String rationale,
            String reviewer
    ) {
        rememberFeedback(job, findingIndex, finding, verdict, rationale, reviewer,
                "", "", "");
    }

    default void rememberFeedback(
            AuditJob job,
            int findingIndex,
            Map<String, Object> finding,
            String verdict,
            String rationale,
            String reviewer,
            String pocStatus,
            String learningNote,
            String targetSeverity
    ) {
    }

    default List<Map<String, Object>> listRuleCandidates() {
        return List.of();
    }

    default Optional<Map<String, Object>> decideRuleCandidate(
            String candidateId,
            String decision,
            String rationale,
            String reviewer
    ) {
        return Optional.empty();
    }

    List<Map<String, Object>> recallPriors(
            AuditJob job,
            String hunter,
            String teamFocus,
            List<Map<String, Object>> endpointSurface,
            List<Map<String, String>> dependencies
    );
}
