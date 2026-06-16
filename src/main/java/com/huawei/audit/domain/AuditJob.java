package com.huawei.audit.domain;

import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayDeque;
import java.util.Set;

public final class AuditJob {
    private final String jobId;
    private final String lang;
    private final Instant createdAt;
    private static final int MAX_LOG_LINES = 2_000;
    private final ArrayDeque<String> logHistory = new ArrayDeque<>();

    private volatile JobStatus status = JobStatus.PENDING;
    private volatile Instant updatedAt;
    private volatile String sourceType = "";
    private volatile String gitUrl = "";
    private volatile Path zipPath;
    private volatile Path workDir;
    private volatile Path projectPath;
    private volatile String error = "";
    private volatile List<Map<String, Object>> findings = List.of();
    private volatile Map<String, Object> stats = Map.of();
    private volatile Map<String, Object> techProfile = Map.of();
    private volatile Map<String, Object> taskSummary = Map.of();
    private volatile Set<String> selectedInterfaceIds = Set.of();
    private volatile boolean submitted;
    private volatile boolean logDone;

    public AuditJob(String jobId, String lang) {
        this(jobId, lang, Instant.now());
    }

    public AuditJob(String jobId, String lang, Instant createdAt) {
        this.jobId = jobId;
        this.lang = lang;
        this.createdAt = createdAt;
        this.updatedAt = createdAt;
    }

    public synchronized void setStatus(JobStatus status) {
        this.status = status;
        this.updatedAt = Instant.now();
    }

    public synchronized void fail(String message) {
        this.error = message == null ? "" : message;
        setStatus(JobStatus.FAILED);
    }

    public void appendLog(String line) {
        synchronized (logHistory) {
            if (logHistory.size() >= MAX_LOG_LINES) {
                logHistory.removeFirst();
            }
            logHistory.addLast(line);
        }
    }

    public String jobId() { return jobId; }
    public String lang() { return lang; }
    public Instant createdAt() { return createdAt; }
    public JobStatus status() { return status; }
    public Instant updatedAt() { return updatedAt; }
    public String sourceType() { return sourceType; }
    public String gitUrl() { return gitUrl; }
    public Path zipPath() { return zipPath; }
    public Path workDir() { return workDir; }
    public Path projectPath() { return projectPath; }
    public String error() { return error; }
    public List<Map<String, Object>> findings() { return findings; }
    public Map<String, Object> stats() { return stats; }
    public Map<String, Object> techProfile() { return techProfile; }
    public Map<String, Object> taskSummary() { return taskSummary; }
    public Set<String> selectedInterfaceIds() { return selectedInterfaceIds; }
    public boolean submitted() { return submitted; }
    public List<String> logHistory() {
        synchronized (logHistory) {
            return List.copyOf(logHistory);
        }
    }
    public boolean logDone() { return logDone; }
    public int findingsCount() { return findings.size(); }

    public void sourceType(String sourceType) { this.sourceType = sourceType; }
    public void gitUrl(String gitUrl) { this.gitUrl = gitUrl; }
    public void zipPath(Path zipPath) { this.zipPath = zipPath; }
    public void workDir(Path workDir) { this.workDir = workDir; }
    public void projectPath(Path projectPath) { this.projectPath = projectPath; }
    public void findings(List<Map<String, Object>> findings) {
        this.findings = List.copyOf(findings);
    }
    public void stats(Map<String, Object> stats) { this.stats = Map.copyOf(stats); }
    public void techProfile(Map<String, Object> techProfile) {
        this.techProfile = Map.copyOf(techProfile);
    }
    public void taskSummary(Map<String, Object> taskSummary) {
        this.taskSummary = Map.copyOf(taskSummary);
    }
    public synchronized boolean submitOnce(Set<String> interfaceIds) {
        if (submitted) {
            return false;
        }
        selectedInterfaceIds = Set.copyOf(interfaceIds);
        submitted = true;
        return true;
    }
    public void logDone(boolean logDone) { this.logDone = logDone; }

    public Map<String, Object> toMeta() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("job_id", jobId);
        meta.put("lang", lang);
        meta.put("status", status.value());
        meta.put("source_type", sourceType);
        meta.put("git_url", gitUrl);
        meta.put("error", error);
        meta.put("created_at", createdAt.toString());
        meta.put("updated_at", updatedAt.toString());
        meta.put("findings_count", findings.size());
        meta.put("selected_interface_ids", selectedInterfaceIds);
        return meta;
    }
}
