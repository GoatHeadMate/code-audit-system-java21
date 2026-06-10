package com.huawei.audit.api;

import com.huawei.audit.domain.AuditJob;
import java.util.List;
import java.util.Map;

public final class ApiDtos {
    private ApiDtos() { }

    public record SubmitResponse(String jobId, String status, String message) { }

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
