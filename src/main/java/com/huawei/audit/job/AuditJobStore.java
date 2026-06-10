package com.huawei.audit.job;

import com.huawei.audit.domain.AuditJob;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class AuditJobStore {
    private final ConcurrentHashMap<String, AuditJob> jobs = new ConcurrentHashMap<>();

    public AuditJob create(String lang) {
        String jobId = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        AuditJob job = new AuditJob(jobId, lang);
        jobs.put(jobId, job);
        return job;
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
