package com.huawei.audit.memory;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.domain.AuditJob;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
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
}
