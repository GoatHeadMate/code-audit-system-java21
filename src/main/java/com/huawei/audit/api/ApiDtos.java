package com.huawei.audit.api;

import com.huawei.audit.domain.AuditJob;
import java.util.List;
import java.util.Map;

public final class ApiDtos {
    private ApiDtos() { }

    public record SubmitResponse(String jobId, String status, String message) { }

    public record InterfacePreviewResponse(
            String jobId,
            String status,
            List<InterfaceOption> interfaces
    ) { }

    public record InterfaceOption(
            String id,
            String protocol,
            List<String> operations,
            String route,
            String className,
            String methodName,
            String filePath,
            int startLine,
            String framework,
            List<String> securityAnnotations
    ) { }

    public record StartAuditRequest(List<String> interfaceIds) {
        public StartAuditRequest {
            interfaceIds = interfaceIds == null
                    ? List.of()
                    : List.copyOf(interfaceIds);
        }
    }

    public record FindingFeedbackRequest(
            String verdict,
            String rationale,
            String reviewer,
            String pocStatus,
            String learningNote,
            String targetSeverity
    ) {
        public FindingFeedbackRequest(
                String verdict,
                String rationale,
                String reviewer
        ) {
            this(verdict, rationale, reviewer, "", "", "");
        }
    }

    public record FindingFeedbackResponse(
            String jobId,
            int findingIndex,
            String verdict,
            String message
    ) { }

    public record RuleCandidatesResponse(
            List<Map<String, Object>> candidates
    ) { }

    public record RuleDecisionRequest(
            String decision,
            String rationale,
            String reviewer
    ) { }

    public record RuleDecisionResponse(
            String candidateId,
            String status,
            String message,
            Map<String, Object> candidate
    ) { }

    public record JobStatusResponse(
            String jobId,
            String status,
            String lang,
            String createdAt,
            String updatedAt,
            String sourceType,
            String gitUrl,
            String error,
            int findingsCount
    ) {
        public static JobStatusResponse from(AuditJob job) {
            return new JobStatusResponse(
                    job.jobId(),
                    job.status().value(),
                    job.lang(),
                    job.createdAt().toString(),
                    job.updatedAt().toString(),
                    job.sourceType(),
                    job.gitUrl(),
                    job.error(),
                    job.findingsCount()
            );
        }
    }

    public record JobListResponse(List<JobStatusResponse> jobs) { }

    public record FindingsResponse(
            String jobId,
            String status,
            List<Map<String, Object>> findings,
            Map<String, Object> stats,
            Map<String, Object> techProfile,
            Map<String, Object> taskSummary
    ) {
        public static FindingsResponse from(AuditJob job) {
            return new FindingsResponse(
                    job.jobId(),
                    job.status().value(),
                    job.findings(),
                    job.stats(),
                    job.techProfile(),
                    job.taskSummary()
            );
        }
    }
}
