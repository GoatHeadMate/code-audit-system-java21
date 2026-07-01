package com.huawei.audit.domain;

import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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
    private volatile String cacheKey = "";
    private volatile boolean submitted;
    private volatile boolean logDone;
    private volatile int roundsCompleted = 0;
    private volatile boolean continuationComplete = true;
    private volatile boolean ceilingHit = false;
    private volatile Set<String> reviewedHunters = Set.of();
    private volatile Set<String> timedOutHunters = Set.of();
    private volatile Set<String> failedHunters = Set.of();
    private volatile int totalCandidateCount = 0;

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
    public String cacheKey() { return cacheKey; }
    public boolean submitted() { return submitted; }
    public List<String> logHistory() {
        synchronized (logHistory) {
            return List.copyOf(logHistory);
        }
    }
    public boolean logDone() { return logDone; }
    public int findingsCount() { return findings.size(); }
    public int roundsCompleted() { return roundsCompleted; }
    public boolean continuationComplete() { return continuationComplete; }
    public boolean ceilingHit() { return ceilingHit; }
    public Set<String> reviewedHunters() { return reviewedHunters; }
    public Set<String> timedOutHunters() { return timedOutHunters; }
    public Set<String> failedHunters() { return failedHunters; }
    public int totalCandidateCount() { return totalCandidateCount; }

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
    public void cacheKey(String cacheKey) { this.cacheKey = cacheKey == null ? "" : cacheKey; }
    public void logDone(boolean logDone) { this.logDone = logDone; }
    public void totalCandidateCount(int totalCandidateCount) {
        this.totalCandidateCount = totalCandidateCount;
    }
    public void restoreSelectedInterfaceIds(Set<String> selectedInterfaceIds) {
        this.selectedInterfaceIds = Set.copyOf(selectedInterfaceIds);
    }

    /**
     * Single entry point for a completed scheduling round: merges this round's
     * hunter outcomes into the job's accumulated state and flips status to
     * PARTIAL (more rounds pending) or DONE (drained or ceiling reached).
     * Synchronized so a concurrent API reader never observes status ahead of
     * the findings/coverage fields it's paired with.
     */
    public synchronized void mergeRoundOutcome(
            int round,
            List<Map<String, Object>> mergedFindings,
            Set<String> reviewedThisRound,
            Set<String> timedOutThisRound,
            Set<String> retryableFailedThisRound,
            boolean moreRoundsRemain,
            boolean ceilingHitNow
    ) {
        this.findings = List.copyOf(mergedFindings);
        this.roundsCompleted = round;
        this.reviewedHunters = union(this.reviewedHunters, reviewedThisRound);
        this.timedOutHunters = union(this.timedOutHunters, timedOutThisRound);
        this.failedHunters = Set.copyOf(retryableFailedThisRound);
        this.continuationComplete = !moreRoundsRemain;
        this.ceilingHit = ceilingHitNow;
        setStatus(moreRoundsRemain ? JobStatus.PARTIAL : JobStatus.DONE);
    }

    /**
     * Rehydrates round-scheduling state from a persisted progress file on
     * restart. Distinct from mergeRoundOutcome: this is "reconstruct prior
     * state," not "a round just finished."
     */
    public synchronized void restoreProgress(
            int roundsCompleted,
            Set<String> reviewedHunters,
            Set<String> timedOutHunters,
            Set<String> failedHunters,
            boolean continuationComplete,
            boolean ceilingHit
    ) {
        this.roundsCompleted = roundsCompleted;
        this.reviewedHunters = Set.copyOf(reviewedHunters);
        this.timedOutHunters = Set.copyOf(timedOutHunters);
        this.failedHunters = Set.copyOf(failedHunters);
        this.continuationComplete = continuationComplete;
        this.ceilingHit = ceilingHit;
    }

    private static Set<String> union(Set<String> existing, Set<String> additional) {
        Set<String> merged = new LinkedHashSet<>(existing);
        merged.addAll(additional);
        return Set.copyOf(merged);
    }

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
        meta.put("rounds_completed", roundsCompleted);
        meta.put("continuation_complete", continuationComplete);
        meta.put("cache_key", cacheKey);
        return meta;
    }
}
