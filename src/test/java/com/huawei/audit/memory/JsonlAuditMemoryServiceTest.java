package com.huawei.audit.memory;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JsonlAuditMemoryServiceTest {
    @TempDir
    Path tempDir;

    @Test
    void appendsFindingsAndRecallsAsPriorsOnly() throws Exception {
        AuditProperties properties = new AuditProperties(
                tempDir,
                "http://127.0.0.1:8011",
                "",
                Duration.ofMinutes(30),
                2,
                15,
                Duration.ofMinutes(30)
        );
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties
        );
        AuditJob job = new AuditJob("memory1", "java");
        job.cacheKey("source-a");
        Map<String, Object> techProfile = Map.of(
                "dependencies",
                List.of(Map.of(
                        "group_id", "org.springframework",
                        "artifact_id", "spring-web"
                ))
        );

        memory.rememberFindings(
                job,
                tempDir.resolve("source"),
                techProfile,
                List.of(Map.of(
                        "rule_id", "ssrf-urlconnection",
                        "vuln_type", "SSRF",
                        "verdict", "CONFIRM",
                        "file_path", "src/main/java/demo/ProxyController.java",
                        "start_line", 42,
                        "http_path", "/proxy",
                        "title", "SSRF through proxy endpoint"
                ))
        );

        Path jsonl = tempDir.resolve("audit-memory").resolve("findings.jsonl");
        assertThat(jsonl).isRegularFile();
        assertThat(Files.readString(jsonl))
                .contains("\"event_type\":\"finding_observed\"")
                .contains("\"memory_policy\":\"historical-prior-only; revalidate from current source\"");

        AuditJob nextJob = new AuditJob("memory2", "java");
        var priors = memory.recallPriors(
                nextJob,
                "ssrf",
                "general",
                List.of(Map.of(
                        "path", "/proxy",
                        "file_path", "src/main/java/demo/ProxyController.java"
                )),
                List.of(Map.of(
                        "group_id", "org.springframework",
                        "artifact_id", "spring-web"
                ))
        );

        assertThat(priors).singleElement().satisfies(prior -> {
            assertThat(prior)
                    .containsEntry("kind", "HISTORICAL_FINDING_PRIOR")
                    .containsEntry("vuln_type", "SSRF")
                    .containsEntry("rule_id", "ssrf-urlconnection")
                    .containsEntry("support_count", 1);
            assertThat(prior.get("policy").toString())
                    .contains("Prior only");
        });
    }

    @Test
    void doesNotRecallWhenOnlyHunterTypeMatches() {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        AuditJob job = new AuditJob("weak-prior1", "java");
        memory.rememberFindings(
                job,
                tempDir.resolve("source"),
                Map.of("dependencies", List.of()),
                List.of(Map.of(
                        "rule_id", "ssrf-old",
                        "vuln_type", "SSRF",
                        "verdict", "CONFIRM",
                        "file_path", "src/main/java/old/LegacyProxy.java",
                        "http_path", "/legacy"
                ))
        );

        var priors = memory.recallPriors(
                new AuditJob("weak-prior2", "java"),
                "ssrf",
                "general",
                List.of(Map.of(
                        "path", "/new",
                        "file_path", "src/main/java/new/NewProxy.java"
                )),
                List.of(Map.of(
                        "group_id", "com.example",
                        "artifact_id", "different"
                ))
        );

        assertThat(priors).isEmpty();
    }

    @Test
    void recallsFalsePositiveFeedbackAsPriorOnly() throws Exception {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        AuditJob job = new AuditJob("feedback-memory1", "java");
        job.techProfile(Map.of(
                "dependencies",
                List.of(Map.of(
                        "group_id", "org.springframework",
                        "artifact_id", "spring-web"
                ))
        ));
        Map<String, Object> finding = Map.of(
                "rule_id", "ssrf-allowlist",
                "vuln_type", "SSRF",
                "file_path", "src/main/java/demo/ProxyController.java",
                "http_path", "/proxy"
        );

        memory.rememberFeedback(
                job,
                0,
                finding,
                "FALSE_POSITIVE",
                "Strict host allowlist blocks attacker URLs",
                "expert"
        );

        Path feedback = tempDir.resolve("audit-memory").resolve("feedback.jsonl");
        assertThat(feedback).isRegularFile();
        assertThat(Files.readString(feedback))
                .contains("\"event_type\":\"finding_feedback\"")
                .contains("\"feedback_verdict\":\"FALSE_POSITIVE\"");

        var priors = memory.recallPriors(
                new AuditJob("feedback-memory2", "java"),
                "ssrf",
                "general",
                List.of(Map.of(
                        "path", "/proxy",
                        "file_path", "src/main/java/demo/ProxyController.java"
                )),
                List.of(Map.of(
                        "group_id", "org.springframework",
                        "artifact_id", "spring-web"
                ))
        );

        assertThat(priors).singleElement().satisfies(prior -> {
            assertThat(prior)
                    .containsEntry("kind", "HISTORICAL_FALSE_POSITIVE_PRIOR")
                    .containsEntry("vuln_type", "SSRF")
                    .containsEntry("rule_id", "ssrf-allowlist");
            assertThat(prior.get("policy").toString())
                    .contains("historical false-positive feedback")
                    .contains("current source");
        });
    }

    @Test
    void storesPocFeedbackAsStructuredLearningEvents() throws Exception {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        AuditJob job = new AuditJob("poc-memory1", "java");
        job.techProfile(Map.of(
                "dependencies",
                List.of(Map.of(
                        "group_id", "org.springframework",
                        "artifact_id", "spring-web"
                ))
        ));
        Map<String, Object> finding = Map.of(
                "rule_id", "cmd-runtime",
                "vuln_type", "COMMAND_INJECTION",
                "file_path", "src/main/java/demo/CmdController.java",
                "http_path", "/cmd"
        );

        memory.rememberFeedback(
                job,
                0,
                finding,
                "POC_SUCCESS",
                "Manual PoC executed calc",
                "expert",
                "SUCCESS",
                "same endpoint shape should be prioritized",
                "CRITICAL"
        );

        Path feedback = tempDir.resolve("audit-memory").resolve("feedback.jsonl");
        assertThat(Files.readString(feedback))
                .contains("\"feedback_verdict\":\"POC_SUCCESS\"")
                .contains("\"learning_signal\":\"TRUE_POSITIVE\"")
                .contains("\"poc_status\":\"SUCCESS\"")
                .contains("\"target_severity\":\"CRITICAL\"");

        var priors = memory.recallPriors(
                new AuditJob("poc-memory2", "java"),
                "code_execution",
                "general",
                List.of(Map.of(
                        "path", "/cmd",
                        "file_path", "src/main/java/demo/CmdController.java"
                )),
                List.of(Map.of(
                        "group_id", "org.springframework",
                        "artifact_id", "spring-web"
                ))
        );

        assertThat(priors).singleElement().satisfies(prior -> {
            assertThat(prior)
                    .containsEntry("kind", "HISTORICAL_POC_SUCCESS_PRIOR")
                    .containsEntry("vuln_type", "COMMAND_INJECTION")
                    .containsEntry("rule_id", "cmd-runtime");
            assertThat(prior.get("policy").toString())
                    .contains("PoC success")
                    .contains("current-source");
        });
    }

    @Test
    void refreshesRuleCandidatesFromFindingsAndFeedback() throws Exception {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        Map<String, Object> finding = Map.of(
                "rule_id", "ssrf-urlconnection",
                "vuln_type", "SSRF",
                "verdict", "CONFIRM",
                "file_path", "src/main/java/demo/ProxyController.java",
                "http_path", "/proxy",
                "start_line", 42
        );
        AuditJob first = new AuditJob("rule-candidate1", "java");
        AuditJob second = new AuditJob("rule-candidate2", "java");

        memory.rememberFindings(
                first,
                tempDir.resolve("source1"),
                Map.of("dependencies", List.of()),
                List.of(finding)
        );
        memory.rememberFeedback(
                second,
                0,
                finding,
                "CONFIRM",
                "Confirmed with manual PoC",
                "expert"
        );

        Path candidates = tempDir.resolve("audit-memory")
                .resolve("rule-candidates.jsonl");
        assertThat(candidates).isRegularFile();
        String content = Files.readString(candidates);
        assertThat(content)
                .contains("\"status\":\"CANDIDATE\"")
                .contains("\"vuln_type\":\"SSRF\"")
                .contains("\"rule_id\":\"ssrf-urlconnection\"")
                .contains("\"support_count\":2")
                .contains("\"total_evidence_count\":2")
                .contains("\"confirm_count\":1")
                .contains("requires human approval");
    }

    @Test
    void approvesRuleCandidateAndWritesApprovedRulePrior() throws Exception {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        Map<String, Object> finding = Map.of(
                "rule_id", "ssrf-urlconnection",
                "vuln_type", "SSRF",
                "verdict", "CONFIRM",
                "file_path", "src/main/java/demo/ProxyController.java",
                "http_path", "/proxy",
                "start_line", 42
        );
        memory.rememberFindings(
                new AuditJob("gate-job1", "java"),
                tempDir.resolve("source"),
                Map.of("dependencies", List.of()),
                List.of(finding)
        );
        memory.rememberFeedback(
                new AuditJob("gate-job2", "java"),
                0,
                finding,
                "CONFIRM",
                "manual PoC",
                "expert"
        );

        var candidates = memory.listRuleCandidates();
        String candidateId = candidates.stream()
                .filter(candidate -> "SSRF".equals(candidate.get("vuln_type")))
                .findFirst()
                .orElseThrow()
                .get("candidate_id")
                .toString();
        assertThat(candidates)
                .anySatisfy(candidate ->
                        assertThat(candidate).containsEntry("status", "CANDIDATE"));

        var decided = memory.decideRuleCandidate(
                candidateId, "APPROVE", "verified by reviewer", "alice");
        assertThat(decided).isPresent();
        assertThat(decided.get()).containsEntry("status", "APPROVED");

        Path approvedFile = tempDir.resolve("audit-memory")
                .resolve("approved-rules.jsonl");
        assertThat(approvedFile).isRegularFile();
        assertThat(Files.readString(approvedFile))
                .contains("\"vuln_type\":\"SSRF\"")
                .contains("approved-rule-prior-only");

        var priors = memory.recallPriors(
                new AuditJob("gate-job3", "java"),
                "ssrf",
                "general",
                List.of(Map.of(
                        "path", "/proxy",
                        "file_path", "src/main/java/demo/ProxyController.java"
                )),
                List.of()
        );
        assertThat(priors)
                .isNotEmpty()
                .allSatisfy(prior ->
                        assertThat(prior.get("policy").toString())
                                .contains("re-validate"));
    }

    @Test
    void returnsEmptyForUnknownRuleCandidateDecision() {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        assertThat(memory.decideRuleCandidate(
                "does-not-exist", "APPROVE", "", "alice")).isEmpty();
    }

    @Test
    void appendsAgentRunTelemetryForSchedulingEvolution() throws Exception {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        AuditJob job = new AuditJob("agent-run1", "java");
        job.cacheKey("source-a");

        memory.rememberAgentRun(job, Map.of(
                "hunter", "ssrf",
                "base_hunter", "ssrf",
                "status", "SUCCESS",
                "duration_ms", 123,
                "slot_wait_ms", 7,
                "findings_count", 2,
                "steps_budget", 36,
                "priority_score", 11,
                "schedule_reason", "approved prior",
                "tools", List.of("read_file", "grep_files")
        ));

        Path telemetry = tempDir.resolve("audit-memory")
                .resolve("agent-runs.jsonl");
        assertThat(telemetry).isRegularFile();
        assertThat(Files.readString(telemetry))
                .contains("\"event_type\":\"agent_run\"")
                .contains("\"hunter\":\"ssrf\"")
                .contains("\"duration_ms\":123")
                .contains("scheduling-prior-only");
    }

    @Test
    void recallReadsOnlyRecentMemoryLines() throws Exception {
        JsonlAuditMemoryService memory = new JsonlAuditMemoryService(
                new ObjectMapper(),
                properties()
        );
        Path jsonl = tempDir.resolve("audit-memory").resolve("findings.jsonl");
        Files.createDirectories(jsonl.getParent());
        ObjectMapper mapper = new ObjectMapper();
        StringBuilder lines = new StringBuilder();
        lines.append(mapper.writeValueAsString(memoryEvent(
                "old-job",
                "old-rule",
                "/target",
                "src/main/java/demo/TargetController.java"
        ))).append(System.lineSeparator());
        for (int index = 0; index < 5_000; index++) {
            lines.append(mapper.writeValueAsString(memoryEvent(
                    "filler-" + index,
                    "filler-rule-" + index,
                    "/filler-" + index,
                    "src/main/java/demo/Filler" + index + ".java"
            ))).append(System.lineSeparator());
        }
        Files.writeString(jsonl, lines.toString(), StandardOpenOption.CREATE);

        var priors = memory.recallPriors(
                new AuditJob("recent-window", "java"),
                "ssrf",
                "general",
                List.of(Map.of(
                        "path", "/target",
                        "file_path", "src/main/java/demo/TargetController.java"
                )),
                List.of()
        );

        assertThat(priors)
                .extracting(prior -> prior.get("rule_id"))
                .doesNotContain("old-rule");
    }

    private AuditProperties properties() {
        return new AuditProperties(
                tempDir,
                "http://127.0.0.1:8011",
                "",
                Duration.ofMinutes(30),
                2,
                15,
                Duration.ofMinutes(30)
        );
    }

    private Map<String, Object> memoryEvent(
            String jobId,
            String ruleId,
            String httpPath,
            String filePath
    ) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("schema_version", 1);
        event.put("event_type", "finding_observed");
        event.put("recorded_at", Instant.now().toString());
        event.put("job_id", jobId);
        event.put("dependency_keys", List.of());
        event.put("rule_id", ruleId);
        event.put("vuln_type", "SSRF");
        event.put("verdict", "CONFIRM");
        event.put("file_path", filePath);
        event.put("http_path", httpPath);
        return event;
    }
}
