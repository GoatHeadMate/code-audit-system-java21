package com.huawei.audit.job;

import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class AuditJobStore {
    private static final int MAX_RETAINED_JOBS = 200;
    private final ConcurrentHashMap<String, AuditJob> jobs = new ConcurrentHashMap<>();

    public AuditJob create(String lang) {
        evictOldJobs();
        String jobId = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        AuditJob job = new AuditJob(jobId, lang);
        jobs.put(jobId, job);
        return job;
    }

    private void evictOldJobs() {
        if (jobs.size() <= MAX_RETAINED_JOBS) {
            return;
        }
        jobs.values().stream()
                .filter(job -> job.status() == JobStatus.DONE
                        || job.status() == JobStatus.FAILED)
                .sorted(Comparator.comparing(AuditJob::createdAt))
                .limit(jobs.size() - MAX_RETAINED_JOBS)
                .forEach(job -> jobs.remove(job.jobId()));
    }

    public Optional<AuditJob> find(String jobId) {
        return Optional.ofNullable(jobs.get(jobId));
    }

    public List<AuditJob> list() {
        return jobs.values().stream()
                .sorted(Comparator.comparing(AuditJob::createdAt).reversed())
                .toList();
    }
}
