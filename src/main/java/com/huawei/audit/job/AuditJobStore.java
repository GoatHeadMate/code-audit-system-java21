package com.huawei.audit.job;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AuditJobStore {
    private static final Logger log = LoggerFactory.getLogger(AuditJobStore.class);
    private static final int MAX_RETAINED_JOBS = 200;
    private final ConcurrentHashMap<String, AuditJob> jobs = new ConcurrentHashMap<>();
    private final List<AuditJob> pendingResume = new ArrayList<>();
    private final ObjectMapper objectMapper;

    public AuditJobStore(AuditProperties properties, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        restoreFromWorkspace(properties.absoluteWorkspace());
    }

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

    /**
     * Jobs restored as PARTIAL on startup (an audit-progress.json showed
     * unfinished continuation and the source is still on disk). Read once by
     * ResumeCoordinator right after the Spring context is fully up.
     */
    List<AuditJob> jobsNeedingResume() {
        return List.copyOf(pendingResume);
    }

    private void restoreFromWorkspace(Path workspace) {
        if (!Files.isDirectory(workspace)) {
            return;
        }
        try (DirectoryStream<Path> dirs =
                     Files.newDirectoryStream(workspace, "audit_*")) {
            for (Path dir : dirs) {
                if (!Files.isDirectory(dir)) {
                    continue;
                }
                String dirName = dir.getFileName().toString();
                String jobId = dirName.substring("audit_".length());
                try {
                    restoreJob(dir, jobId);
                } catch (Exception e) {
                    log.warn("跳过恢复 {}: {}", dirName, e.getMessage());
                }
            }
        } catch (IOException e) {
            log.warn("扫描 workspace 失败: {}", e.getMessage());
        }
        log.info("从 workspace 恢复了 {} 个历史任务,其中 {} 个待续跑",
                jobs.size(), pendingResume.size());
    }

    @SuppressWarnings("unchecked")
    private void restoreJob(Path dir, String jobId) throws Exception {
        Path metaFile = dir.resolve("job-meta.json");
        Path findingsFile = dir.resolve("findings.json");
        Path progressFile = dir.resolve("audit-progress.json");
        Path projectDir = dir.resolve("project");
        boolean hasProgress = Files.isRegularFile(progressFile);
        boolean projectStillPresent = Files.isDirectory(projectDir);

        String lang = "java";
        String sourceType = "";
        String gitUrl = "";
        String error = "";
        Instant createdAt = Files.getLastModifiedTime(dir).toInstant();
        JobStatus status;
        JsonNode meta = null;

        if (Files.exists(metaFile)) {
            meta = objectMapper.readTree(Files.readString(metaFile));
            lang = meta.path("lang").asText("java");
            sourceType = meta.path("source_type").asText("");
            gitUrl = meta.path("git_url").asText("");
            error = meta.path("error").asText("");
            String createdStr = meta.path("created_at").asText("");
            if (!createdStr.isEmpty()) {
                createdAt = Instant.parse(createdStr);
            }
            if ("done".equals(meta.path("status").asText())) {
                status = JobStatus.DONE;
            } else if (hasProgress && projectStillPresent) {
                status = JobStatus.PARTIAL;
            } else {
                status = JobStatus.FAILED;
                error = error.isBlank() ? "未完成的审计任务（源码缺失，无法续跑）" : error;
            }
        } else if (Files.exists(findingsFile) && !hasProgress) {
            status = JobStatus.DONE;
        } else if (hasProgress && projectStillPresent) {
            status = JobStatus.PARTIAL;
        } else {
            status = JobStatus.FAILED;
            error = "未完成的审计任务";
        }

        AuditJob job = new AuditJob(jobId, lang, createdAt);
        job.submitOnce(Set.of());
        job.sourceType(sourceType);
        job.gitUrl(gitUrl);
        job.workDir(dir);
        job.logDone(true);

        if ((status == JobStatus.DONE || status == JobStatus.PARTIAL)
                && Files.exists(findingsFile)) {
            List<Map<String, Object>> findings = objectMapper.readValue(
                    Files.readString(findingsFile),
                    objectMapper.getTypeFactory()
                            .constructCollectionType(List.class, Map.class)
            );
            job.findings(findings);

            Path coverageFile = dir.resolve("evidence")
                    .resolve("whitebox").resolve("coverage.json");
            if (Files.exists(coverageFile)) {
                Map<String, Object> stats = objectMapper.readValue(
                        Files.readString(coverageFile), Map.class);
                job.stats(stats);
            }
        }

        if ((status == JobStatus.PARTIAL || status == JobStatus.DONE)
                && hasProgress && projectStillPresent) {
            JsonNode progress = objectMapper.readTree(progressFile.toFile());
            job.restoreProgress(
                    progress.path("round").asInt(0),
                    toStringSet(progress.path("reviewed")),
                    toStringSet(progress.path("timed_out")),
                    toStringSet(progress.path("failed_retryable")),
                    progress.path("complete").asBoolean(status != JobStatus.PARTIAL),
                    progress.path("ceiling_hit").asBoolean(false)
            );
            job.totalCandidateCount(progress.path("total_candidates").asInt(0));
            if (meta != null) {
                job.restoreSelectedInterfaceIds(toStringSet(meta.path("selected_interface_ids")));
                job.cacheKey(meta.path("cache_key").asText(""));
            }
            job.projectPath(resolveSourceRoot(projectDir));
        }

        if (status == JobStatus.PARTIAL) {
            job.setStatus(JobStatus.PARTIAL);
            jobs.put(jobId, job);
            pendingResume.add(job);
            return;
        }

        if (status == JobStatus.FAILED) {
            job.fail(error);
        } else {
            job.setStatus(status);
        }

        jobs.put(jobId, job);
    }

    private Set<String> toStringSet(JsonNode arrayNode) {
        Set<String> values = new LinkedHashSet<>();
        if (arrayNode != null && arrayNode.isArray()) {
            arrayNode.forEach(node -> values.add(node.asText()));
        }
        return values;
    }

    private Path resolveSourceRoot(Path projectDir) throws IOException {
        try (var children = Files.list(projectDir)) {
            var entries = children.toList();
            return entries.size() == 1 && Files.isDirectory(entries.getFirst())
                    ? entries.getFirst()
                    : projectDir;
        }
    }
}
