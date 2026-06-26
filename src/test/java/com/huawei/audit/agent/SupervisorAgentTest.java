package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.hunter.FindingParser;
import com.huawei.audit.job.JobLogBroker;
import dev.langchain4j.data.message.ChatMessage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.mockito.ArgumentCaptor;
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
                Map.of(
                        "sql_injection", taskFile("sql_injection", 0).toString(),
                        "code_execution", taskFile("code_execution", 1).toString(),
                        "authorization", authorizationTaskFile().toString(),
                        "ssrf", taskFile("ssrf", 1).toString(),
                        "unsafe_parsing", taskFile("unsafe_parsing", 0).toString()
                ),
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
                Map.of("sql_injection", taskFile("sql_injection", 1).toString()),
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
                Map.of("code_execution", taskFile("code_execution", 1).toString()),
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

    @Test
    @SuppressWarnings("unchecked")
    void subagentLoadsSkillThroughAgentScopeToolInsteadOfInliningSkill()
            throws Exception {
        ClaudeAgentSupervisorModel model = mock(ClaudeAgentSupervisorModel.class);
        when(model.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {"selected_hunters":["sql_injection"],"rationale":"ok","findings":[]}
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
        AuditJob job = new AuditJob("skill123", "java");
        job.workDir(tempDir.resolve("audit_skill123"));
        java.nio.file.Files.createDirectories(job.workDir());

        supervisor.run(
                job,
                Path.of("source"),
                Map.of(),
                List.of("sql_injection"),
                Map.of("sql_injection", "tasks/sql.json"),
                Map.of("sql_injection", "audit-sql-injection"),
                Map.of()
        );

        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(model).supervise(any(), any(), any(), agentsCaptor.capture(), any());
        ClaudeGateway.AgentDef agent = agentsCaptor.getValue().get("sql_injection");

        assertThat(agent.skills()).containsExactly("audit-sql-injection_audit");
        assertThat(agent.tools()).containsExactly(
                "read_file",
                "glob_files",
                "grep_files",
                "load_skill_through_path"
        );
        assertThat(agent.prompt())
                .contains("load_skill_through_path(skillId=\"audit-sql-injection_audit\", path=\"SKILL.md\")")
                .contains("tasks/sql.json")
                .doesNotContain("# SQL 注入判断知识")
                .doesNotContain("specialistKnowledge");
    }

    @Test
    @SuppressWarnings("unchecked")
    void skipsEvidencePackagesWithoutCandidateReviewWork()
            throws Exception {
        ClaudeAgentSupervisorModel model = mock(ClaudeAgentSupervisorModel.class);
        when(model.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {"selected_hunters":["code_execution"],"rationale":"ok","findings":[]}
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
        AuditJob job = new AuditJob("filter123", "java");
        job.workDir(tempDir.resolve("audit_filter123"));
        Files.createDirectories(job.workDir());

        supervisor.run(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "ssrf", "file_operations"),
                Map.of(
                        "code_execution", taskFile("code_execution", 2).toString(),
                        "ssrf", taskFile("ssrf", 0).toString(),
                        "file_operations", taskFile("file_operations", 0).toString()
                ),
                Map.of(),
                Map.of()
        );

        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(model).supervise(any(), any(), any(), agentsCaptor.capture(), any());

        assertThat(agentsCaptor.getValue())
                .containsOnlyKeys("code_execution");
    }

    @Test
    @SuppressWarnings("unchecked")
    void promptsSupervisorToSpawnHuntersInParallel()
            throws Exception {
        ClaudeAgentSupervisorModel model = mock(ClaudeAgentSupervisorModel.class);
        when(model.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {"selected_hunters":["code_execution","authorization"],"rationale":"ok","findings":[]}
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
        AuditJob job = new AuditJob("parallel123", "java");
        job.workDir(tempDir.resolve("audit_parallel123"));
        Files.createDirectories(job.workDir());

        supervisor.run(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "authorization"),
                Map.of(
                        "code_execution", taskFile("code_execution", 1).toString(),
                        "authorization", authorizationTaskFile().toString()
                ),
                Map.of(),
                Map.of()
        );

        ArgumentCaptor<List<ChatMessage>> messagesCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(model).supervise(any(), any(), messagesCaptor.capture(), any(), any());
        String prompt = messagesCaptor.getValue().toString();

        assertThat(prompt)
                .contains("ALL agent_spawn calls together")
                .contains("in parallel")
                .contains("Maximum agent_spawn calls per assistant turn: 2")
                .doesNotContain("serially")
                .doesNotContain("one at a time");
    }

    @Test
    void skipsAgentScopeWhenNoEvidencePackageHasReviewWork()
            throws Exception {
        ClaudeAgentSupervisorModel model = mock(ClaudeAgentSupervisorModel.class);
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
        AuditJob job = new AuditJob("empty123", "java");
        job.workDir(tempDir.resolve("audit_empty123"));
        Files.createDirectories(job.workDir());

        var result = supervisor.run(
                job,
                Path.of("source"),
                Map.of(),
                List.of("ssrf", "file_operations"),
                Map.of(
                        "ssrf", taskFile("ssrf", 0).toString(),
                        "file_operations", taskFile("file_operations", 0).toString()
                ),
                Map.of(),
                Map.of()
        );

        verify(model, never()).supervise(any(), any(), any(), any(), any());
        assertThat(result.selectedHunters()).isEmpty();
        assertThat(result.findings()).isEmpty();
        assertThat(job.workDir().resolve("supervisor-response.txt"))
                .isRegularFile();
    }

    private Path taskFile(String hunter, int candidateCount) throws Exception {
        Path tasks = tempDir.resolve("tasks");
        Files.createDirectories(tasks);
        Path task = tasks.resolve(hunter + "-" + candidateCount + ".json");
        Files.writeString(task, """
                {"hunter":"%s","candidate_count":%d,"stored_candidate_count":0}
                """.formatted(hunter, candidateCount));
        return task;
    }

    private Path authorizationTaskFile() throws Exception {
        Path tasks = tempDir.resolve("tasks");
        Files.createDirectories(tasks);
        Path task = tasks.resolve("authorization-surface.json");
        Files.writeString(task, """
                {
                  "hunter":"authorization",
                  "candidate_count":0,
                  "stored_candidate_count":0,
                  "authorization_surface":[{"path":"/execute/cmd"}]
                }
                """);
        return task;
    }
}
