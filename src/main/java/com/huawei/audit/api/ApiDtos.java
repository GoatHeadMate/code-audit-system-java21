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

    public record AutoFindingFeedbackResponse(
            String jobId,
            int evaluatedCount,
            Map<String, Integer> verdictCounts,
            List<AutoFindingFeedbackItem> evaluations,
            String message
    ) { }

    public record AutoFindingFeedbackItem(
            int findingIndex,
            String verdict,
            String rationale,
            String pocStatus,
            String targetSeverity,
            String learningNote,
            boolean recorded
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
            int findingsCount,
            ProgressInfo progress
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
                    job.findingsCount(),
                    ProgressInfo.from(job)
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
            Map<String, Object> taskSummary,
            ProgressInfo progress
    ) {
        public static FindingsResponse from(AuditJob job) {
            return new FindingsResponse(
                    job.jobId(),
                    job.status().value(),
                    job.findings(),
                    job.stats(),
                    job.techProfile(),
                    job.taskSummary(),
                    ProgressInfo.from(job)
            );
        }
    }

    /**
     * Round-scheduling coverage for a job. `complete` means no further
     * automatic continuation will happen (either the candidate pool drained,
     * or the round/time safety ceiling was reached) — not that every
     * candidate was necessarily reviewed; check ceilingHit for that
     * distinction.
     */
    public record ProgressInfo(
            int round,
            int totalCandidates,
            int reviewedCount,
            int timedOutCount,
            int retryableFailureCount,
            int remainingCount,
            boolean complete,
            boolean ceilingHit
    ) {
        public static ProgressInfo from(AuditJob job) {
            int total = job.totalCandidateCount();
            int reviewed = job.reviewedHunters().size();
            int timedOut = job.timedOutHunters().size();
            int failed = job.failedHunters().size();
            int remaining = Math.max(0, total - reviewed - timedOut);
            return new ProgressInfo(
                    job.roundsCompleted(),
                    total,
                    reviewed,
                    timedOut,
                    failed,
                    remaining,
                    job.continuationComplete(),
                    job.ceilingHit()
            );
        }
    }
}
