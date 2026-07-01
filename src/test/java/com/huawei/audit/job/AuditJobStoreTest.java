package com.huawei.audit.job;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditJobStoreTest {

    @TempDir
    Path workspace;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void restoresPartialJobWhenProgressFileAndProjectPresent() throws Exception {
        Path dir = jobDir("partial1");
        writeMeta(dir, "partial1", "partial", Set.of(), "");
        writeFindings(dir, """
                [{"rule_id":"r1","vuln_type":"SSRF","severity":"HIGH"}]
                """);
        writeProgress(dir, 1, 5, """
                "reviewed":["ssrf"],"timed_out":[],"failed_retryable":["code_execution"]
                """);
        Path sourceRoot = dir.resolve("project").resolve("myapp");
        Files.createDirectories(sourceRoot);
        Files.writeString(sourceRoot.resolve("pom.xml"), "<project/>");

        AuditJobStore store = newStore();

        AuditJob job = store.find("partial1").orElseThrow();
        assertThat(job.status()).isEqualTo(JobStatus.PARTIAL);
        assertThat(job.reviewedHunters()).containsExactly("ssrf");
        assertThat(job.timedOutHunters()).isEmpty();
        assertThat(job.failedHunters()).containsExactly("code_execution");
        assertThat(job.totalCandidateCount()).isEqualTo(5);
        assertThat(job.projectPath()).isEqualTo(sourceRoot);
        assertThat(job.findings()).hasSize(1);
    }

    @Test
    void failsWhenProgressFilePresentButProjectSourceMissing() throws Exception {
        Path dir = jobDir("partialnosrc");
        writeMeta(dir, "partialnosrc", "partial", Set.of(), "");
        writeFindings(dir, "[]");
        writeProgress(dir, 1, 5, """
                "reviewed":[],"timed_out":[],"failed_retryable":["ssrf"]
                """);
        // No project/ directory written — source no longer present.

        AuditJobStore store = newStore();

        AuditJob job = store.find("partialnosrc").orElseThrow();
        assertThat(job.status()).isEqualTo(JobStatus.FAILED);
    }

    @Test
    void restoresSelectedInterfaceIdsAndCacheKeyForPartialJob() throws Exception {
        Path dir = jobDir("partialids");
        writeMeta(dir, "partialids", "partial",
                Set.of("iface-1", "iface-2"), "abc123");
        writeFindings(dir, "[]");
        writeProgress(dir, 1, 2, """
                "reviewed":[],"timed_out":[],"failed_retryable":[]
                """);
        Files.createDirectories(dir.resolve("project"));

        AuditJobStore store = newStore();

        AuditJob job = store.find("partialids").orElseThrow();
        assertThat(job.selectedInterfaceIds())
                .containsExactlyInAnyOrder("iface-1", "iface-2");
        assertThat(job.cacheKey()).isEqualTo("abc123");
    }

    @Test
    void legacyDoneJobWithoutMetaFileStillRestoresAsDone() throws Exception {
        Path dir = jobDir("legacy1");
        writeFindings(dir, """
                [{"rule_id":"r1","vuln_type":"SQL_INJECTION"}]
                """);
        // No job-meta.json, no audit-progress.json — pre-existing legacy layout.

        AuditJobStore store = newStore();

        AuditJob job = store.find("legacy1").orElseThrow();
        assertThat(job.status()).isEqualTo(JobStatus.DONE);
        assertThat(job.findings()).hasSize(1);
    }

    @Test
    void jobsNeedingResumeReturnsOnlyPartialJobs() throws Exception {
        Path doneDir = jobDir("done1");
        writeFindings(doneDir, "[]");

        Path failedDir = jobDir("failed1");
        // Empty directory: no meta, no findings, no progress -> FAILED.
        Files.createDirectories(failedDir);

        Path partialDir = jobDir("partial2");
        writeMeta(partialDir, "partial2", "partial", Set.of(), "");
        writeFindings(partialDir, "[]");
        writeProgress(partialDir, 1, 1, """
                "reviewed":[],"timed_out":[],"failed_retryable":["ssrf"]
                """);
        Files.createDirectories(partialDir.resolve("project"));

        AuditJobStore store = newStore();

        assertThat(store.jobsNeedingResume())
                .extracting(AuditJob::jobId)
                .containsExactly("partial2");
    }

    private AuditJobStore newStore() {
        AuditProperties properties = new AuditProperties(
                workspace, "", "", null, 2, 15, null);
        return new AuditJobStore(properties, objectMapper);
    }

    private Path jobDir(String jobId) throws Exception {
        Path dir = workspace.resolve("audit_" + jobId);
        Files.createDirectories(dir);
        return dir;
    }

    private void writeMeta(
            Path dir, String jobId, String status,
            Set<String> selectedInterfaceIds, String cacheKey
    ) throws Exception {
        String idsJson = selectedInterfaceIds.stream()
                .map(id -> "\"" + id + "\"")
                .collect(Collectors.joining(",", "[", "]"));
        Files.writeString(dir.resolve("job-meta.json"), """
                {
                  "job_id":"%s","lang":"java","status":"%s",
                  "source_type":"zip","git_url":"","error":"",
                  "created_at":"%s","updated_at":"%s","findings_count":0,
                  "selected_interface_ids":%s,"cache_key":"%s"
                }
                """.formatted(jobId, status, Instant.now(), Instant.now(),
                idsJson, cacheKey));
    }

    private void writeFindings(Path dir, String json) throws Exception {
        Files.writeString(dir.resolve("findings.json"), json);
    }

    private void writeProgress(
            Path dir, int round, int totalCandidates, String setFields
    ) throws Exception {
        Files.writeString(dir.resolve("audit-progress.json"), """
                {
                  "round":%d,"total_candidates":%d,%s,
                  "complete":false,"ceiling_hit":false,"updated_at":"%s"
                }
                """.formatted(round, totalCandidates, setFields, Instant.now()));
    }
}
