package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.hunter.FindingParser;
import com.huawei.audit.job.JobLogBroker;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SupervisorAgentTest {

    @TempDir
    Path tempDir;

    @Test
    void filtersDelegationToCandidateWhitelistAndMandatoryHunters()
            throws Exception {
        ClaudeAgentSupervisorModel model = mock(ClaudeAgentSupervisorModel.class);
        when(model.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {
                  "selected_hunters": ["ssrf", "not-a-real-agent"],
                  "rationale": "Spring HTTP client surface",
                  "findings": [{
                    "rule_id": "ssrf-1",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "file_path": "src/Test.java",
                    "start_line": 12,
                    "message": "User-controlled URL",
                    "vuln_type": "SSRF"
                  }]
                }
                """);

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                model,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(
                        true,
                        10,
                        5,
                        80
                ),
                new JobLogBroker()
        );
        AuditJob job = new AuditJob("super123", "java");
        job.workDir(tempDir.resolve("audit_super123"));
        java.nio.file.Files.createDirectories(job.workDir());

        var result = supervisor.run(
                job,
                Path.of("source"),
                Map.of("web_framework", "Spring Boot"),
                List.of(
                        "sql_injection",
                        "code_execution",
                        "authorization",
                        "ssrf",
                        "unsafe_parsing"
                ),
                Map.of(),
                Map.of(),
                Map.of()
        );

        assertThat(result.selectedHunters())
                .contains(
                        "code_execution",
                        "authorization",
                        "ssrf"
                )
                .doesNotContain("not-a-real-agent")
                .hasSizeLessThanOrEqualTo(8);
        assertThat(result.findings()).hasSize(1);
    }

    @Test
    void parsesFencedEnvelopeAfterTextContainingTemplateBraces()
            throws Exception {
        ClaudeAgentSupervisorModel model = mock(ClaudeAgentSupervisorModel.class);
        when(model.supervise(any(), any(), any(), any(), any())).thenReturn("""
                All subagent audits completed.
                SQL Injection: `${orderByClause}` requires review.

                ```json
                {
                  "selected_hunters": ["sql_injection"],
                  "rationale": "Aggregated specialist results",
                  "findings": [{
                    "rule_id": "sqli-mybatis-unsafe",
                    "title": "Unsafe MyBatis interpolation",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "file_path": "src/Mapper.xml",
                    "start_line": 42,
                    "message": "Dynamic ORDER BY",
                    "evidence": "${orderByClause}",
                    "vuln_type": "SQL_INJECTION",
                    "data_flow_path": []
                  }]
                }
                ```
                """);

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                model,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(
                        true,
                        10,
                        5,
                        80
                ),
                new JobLogBroker()
        );
        AuditJob job = new AuditJob("fenced123", "java");
        job.workDir(tempDir.resolve("audit_fenced123"));
        java.nio.file.Files.createDirectories(job.workDir());

        var result = supervisor.run(
                job,
                Path.of("source"),
                Map.of(),
                List.of(
                        "sql_injection",
                        "code_execution",
                        "authorization"
                ),
                Map.of(),
                Map.of(),
                Map.of()
        );

        assertThat(result.findings()).hasSize(1);
        assertThat(result.findings().getFirst())
                .containsEntry("rule_id", "sqli-mybatis-unsafe")
                .containsEntry("vulnerability_type", "SQL_INJECTION");
        assertThat(job.workDir().resolve("supervisor-response.txt"))
                .isRegularFile();
    }

    @Test
    void rejectsPlanningTextInsteadOfReturningEmptyFindings()
            throws Exception {
        ClaudeAgentSupervisorModel model = mock(ClaudeAgentSupervisorModel.class);
        when(model.supervise(any(), any(), any(), any(), any())).thenReturn(
                "I'll start by examining the project structure, then delegate."
        );

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                model,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(
                        true,
                        10,
                        5,
                        80
                ),
                new JobLogBroker()
        );
        AuditJob job = new AuditJob("plain123", "java");
        job.workDir(tempDir.resolve("audit_plain123"));
        java.nio.file.Files.createDirectories(job.workDir());

        assertThatThrownBy(() -> supervisor.run(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "authorization", "ssrf"),
                Map.of(),
                Map.of(),
                Map.of()
        ))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("supervisor response unparseable")
                .hasMessageContaining("supervisor did not return a JSON object")
                .hasMessageContaining("I'll start by examining");

        assertThat(job.workDir().resolve("supervisor-response.txt"))
                .isRegularFile();
    }
}
