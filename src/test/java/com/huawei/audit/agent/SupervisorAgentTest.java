package com.huawei.audit.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.hunter.FindingParser;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.memory.AuditMemoryService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SupervisorAgentTest {

    @TempDir
    Path tempDir;

    @Test
    void filtersDelegationToCandidateWhitelistAndMandatoryHunters()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Map<String, ClaudeGateway.AgentDef> agents = invocation.getArgument(3);
                    String hunter = agents.keySet().iterator().next();
                    if ("ssrf".equals(hunter)) {
                        return """
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
                                """;
                    }
                    return """
                            {"selected_hunters":["%s"],"rationale":"ok","findings":[]}
                            """.formatted(hunter);
                });

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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

        var result = supervisor.runRound(
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
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        assertThat(result.reviewed())
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
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any())).thenReturn("""
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
                gateway,
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

        var result = supervisor.runRound(
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
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
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
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any())).thenReturn(
                "I'll start by examining the project structure, then delegate."
        );

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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

        var result = supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "authorization", "ssrf"),
                Map.of("code_execution", taskFile("code_execution", 1).toString()),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        assertThat(result.timedOut()).containsExactly("code_execution");
        assertThat(result.reviewed()).isEmpty();
        assertThat(result.retryableFailures()).isEmpty();
        assertThat(result.findings()).isEmpty();
        assertThat(result.rationale())
                .contains("supervisor response unparseable")
                .contains("supervisor did not return a JSON object")
                .contains("I'll start by examining");

        assertThat(job.workDir().resolve("supervisor-response-code_execution.txt"))
                .isRegularFile();
    }

    @Test
    @SuppressWarnings("unchecked")
    void subagentLoadsAgentScopeSkillInsteadOfEmbeddingRules()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {"selected_hunters":["sql_injection"],"rationale":"ok","findings":[]}
                """);

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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
        Path skillDir = job.workDir().resolve("skills/audit-sql-injection");
        Files.createDirectories(skillDir);
        Files.writeString(skillDir.resolve("SKILL.md"), """
                ---
                name: audit-sql-injection
                description: SQL rules
                ---

                # SQL 注入判断知识

                Confirm only with source-level SQL construction evidence.
                """);

        supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("sql_injection"),
                Map.of("sql_injection", "tasks/sql.json"),
                Map.of("sql_injection", "audit-sql-injection"),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(gateway).supervise(any(), any(), any(), agentsCaptor.capture(), any());
        ClaudeGateway.AgentDef agent = agentsCaptor.getValue().get("sql_injection");

        assertThat(agent.tools()).containsExactly(
                "read_file",
                "glob_files",
                "grep_files",
                "load_skill_through_path"
        );
        assertThat(agent.workspace()).isNotNull();
        assertThat(agent.workspace().resolve("AGENTS.md")).isRegularFile();
        assertThat(agent.workspace()
                .resolve("skills")
                .resolve("audit-sql-injection")
                .resolve("SKILL.md"))
                .isRegularFile()
                .hasContent("""
                        ---
                        name: audit-sql-injection
                        description: SQL rules
                        ---

                        # SQL 注入判断知识

                        Confirm only with source-level SQL construction evidence.
                        """);
        assertThat(agent.prompt())
                .contains("load_skill_through_path(skillId=\"audit-sql-injection\", path=\"SKILL.md\")")
                .contains("tasks/sql.json")
                .doesNotContain("Embedded judgment rules:")
                .doesNotContain("# SQL 注入判断知识")
                .doesNotContain("specialistKnowledge");
    }

    @Test
    @SuppressWarnings("unchecked")
    void skipsEvidencePackagesWithoutCandidateReviewWork()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {"selected_hunters":["code_execution"],"rationale":"ok","findings":[]}
                """);

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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

        supervisor.runRound(
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
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(gateway).supervise(any(), any(), any(), agentsCaptor.capture(), any());

        assertThat(agentsCaptor.getValue())
                .containsOnlyKeys("code_execution");
    }

    @Test
    @SuppressWarnings("unchecked")
    void runsEachHunterInSeparateVirtualThreadSupervisorSession()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        CountDownLatch bothSessionsStarted = new CountDownLatch(2);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Map<String, ClaudeGateway.AgentDef> agents = invocation.getArgument(3);
                    String hunter = agents.keySet().iterator().next();
                    bothSessionsStarted.countDown();
                    if (!bothSessionsStarted.await(2, TimeUnit.SECONDS)) {
                        throw new AssertionError(
                                "hunter supervisor sessions did not run concurrently"
                        );
                    }
                    return """
                            {"selected_hunters":["%s"],"rationale":"ok","findings":[]}
                            """.formatted(hunter);
                });

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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

        supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "authorization"),
                Map.of(
                        "code_execution", taskFile("code_execution", 1).toString(),
                        "authorization", authorizationTaskFile().toString()
                ),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        ArgumentCaptor<String> promptCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(gateway, times(2)).supervise(
                any(),
                any(),
                promptCaptor.capture(),
                agentsCaptor.capture(),
                any()
        );

        assertThat(agentsCaptor.getAllValues())
                .allSatisfy(singleAgent -> assertThat(singleAgent).hasSize(1));
        assertThat(agentsCaptor.getAllValues().stream()
                .flatMap(singleAgent -> singleAgent.keySet().stream())
                .toList())
                .containsExactlyInAnyOrder("code_execution", "authorization");
        assertThat(promptCaptor.getAllValues())
                .allSatisfy(prompt -> assertThat(prompt)
                        .contains("EXACTLY ONE agent_spawn call in this session")
                        .contains("Maximum agent_spawn calls per assistant turn: 1")
                        .doesNotContain("in parallel"));
    }

    @Test
    void limitsConcurrentHunterSupervisorSessions()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maxObserved = new AtomicInteger();
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    int current = active.incrementAndGet();
                    maxObserved.accumulateAndGet(current, Math::max);
                    try {
                        Thread.sleep(100);
                        Map<String, ClaudeGateway.AgentDef> agents = invocation.getArgument(3);
                        String hunter = agents.keySet().iterator().next();
                        return """
                                {"selected_hunters":["%s"],"rationale":"ok","findings":[]}
                                """.formatted(hunter);
                    } finally {
                        active.decrementAndGet();
                    }
                });

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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
        AuditJob job = new AuditJob("limited123", "java");
        job.workDir(tempDir.resolve("audit_limited123"));
        Files.createDirectories(job.workDir());

        supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "authorization", "ssrf"),
                Map.of(
                        "code_execution", taskFile("code_execution", 1).toString(),
                        "authorization", authorizationTaskFile().toString(),
                        "ssrf", taskFile("ssrf", 1).toString()
                ),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        verify(gateway, times(3)).supervise(any(), any(), any(), any(), any());
        assertThat(maxObserved.get()).isLessThanOrEqualTo(2);
    }

    @Test
    void skipsAgentScopeWhenNoEvidencePackageHasReviewWork()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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

        var result = supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("ssrf", "file_operations"),
                Map.of(
                        "ssrf", taskFile("ssrf", 0).toString(),
                        "file_operations", taskFile("file_operations", 0).toString()
                ),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        verify(gateway, never()).supervise(any(), any(), any(), any(), any());
        assertThat(result.reviewed()).isEmpty();
        assertThat(result.findings()).isEmpty();
        assertThat(job.workDir().resolve("supervisor-response.txt"))
                .isRegularFile();
    }

    @Test
    @SuppressWarnings("unchecked")
    void appliesHarnessDecisionBudgetAndRecordsAgentRun()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Map<String, ClaudeGateway.AgentDef> agents = invocation.getArgument(3);
                    String hunter = agents.keySet().iterator().next();
                    return """
                            {"selected_hunters":["%s"],"rationale":"ok","findings":[]}
                            """.formatted(hunter);
                });
        List<Map<String, Object>> runs = new ArrayList<>();
        AuditMemoryService memory = new AuditMemoryService() {
            @Override
            public void rememberFindings(
                    AuditJob job,
                    Path sourceRoot,
                    Map<String, Object> techProfile,
                    List<Map<String, Object>> findings
            ) {
            }

            @Override
            public List<Map<String, Object>> recallPriors(
                    AuditJob job,
                    String hunter,
                    String teamFocus,
                    List<Map<String, Object>> endpointSurface,
                    List<Map<String, String>> dependencies
            ) {
                return List.of();
            }

            @Override
            public void rememberAgentRun(AuditJob job, Map<String, Object> agentRun) {
                runs.add(agentRun);
            }
        };

        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(
                        true,
                        10,
                        5,
                        80
                ),
                new JobLogBroker(),
                memory
        );
        AuditJob job = new AuditJob("budget123", "java");
        job.workDir(tempDir.resolve("audit_budget123"));
        Files.createDirectories(job.workDir());

        supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("ssrf"),
                Map.of("ssrf", taskFileWithDecision("ssrf", 36, 11).toString()),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(gateway).supervise(any(), any(), any(), agentsCaptor.capture(), any());
        ClaudeGateway.AgentDef agent = agentsCaptor.getValue().get("ssrf");
        assertThat(agent.steps()).isEqualTo(36);
        assertThat(agent.priority()).isEqualTo(11);
        assertThat(agent.scheduleReason()).contains("approved prior");

        assertThat(runs).singleElement().satisfies(run -> {
            assertThat(run)
                    .containsEntry("hunter", "ssrf")
                    .containsEntry("status", "SUCCESS")
                    .containsEntry("findings_count", 0)
                    .containsEntry("steps_budget", 36)
                    .containsEntry("priority_score", 11);
            assertThat(run).containsKeys("duration_ms", "slot_wait_ms", "tools");
        });
    }

    @Test
    @SuppressWarnings("unchecked")
    void keepsEndpointReviewSurfaceWithoutCandidatePaths()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {"selected_hunters":["http_output"],"rationale":"surface","findings":[]}
                """);
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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
        AuditJob job = new AuditJob("surface123", "java");
        job.workDir(tempDir.resolve("audit_surface123"));
        Files.createDirectories(job.workDir());

        var result = supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("http_output"),
                Map.of("http_output", endpointSurfaceTask("http_output").toString()),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(gateway).supervise(any(), any(), any(), agentsCaptor.capture(), any());

        assertThat(agentsCaptor.getValue()).containsOnlyKeys("http_output");
        assertThat(result.reviewed()).containsExactly("http_output");
    }

    @Test
    @SuppressWarnings("unchecked")
    void keepsEndpointReviewChunkOnlyBatchWithoutInlineSurface()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any())).thenReturn("""
                {"selected_hunters":["http_output_batch_2"],"rationale":"surface batch","findings":[]}
                """);
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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
        AuditJob job = new AuditJob("surfacebatch123", "java");
        job.workDir(tempDir.resolve("audit_surfacebatch123"));
        Files.createDirectories(job.workDir());

        var result = supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("http_output_batch_2"),
                Map.of("http_output_batch_2",
                        endpointChunkOnlyTask("http_output").toString()),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        ArgumentCaptor<Map<String, ClaudeGateway.AgentDef>> agentsCaptor =
                ArgumentCaptor.forClass(Map.class);
        verify(gateway).supervise(any(), any(), any(), agentsCaptor.capture(), any());

        assertThat(agentsCaptor.getValue()).containsOnlyKeys("http_output_batch_2");
        assertThat(result.reviewed()).containsExactly("http_output_batch_2");
    }

    @Test
    void returnsRawFindingsWithoutConsolidatingWithinARound()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Map<String, ClaudeGateway.AgentDef> agents = invocation.getArgument(3);
                    String hunter = agents.keySet().iterator().next();
                    return """
                            {
                              "selected_hunters":["%s"],
                              "rationale":"duplicate surface",
                              "findings":[{
                                "rule_id":"cmdinj-%s",
                                "title":"Runtime exec",
                                "severity":"CRITICAL",
                                "confidence":"HIGH",
                                "vuln_type":"COMMAND_INJECTION",
                                "file_path":"src/main/java/demo/Rce.java",
                                "http_path":"/rce/runtime/exec",
                                "verdict":"CONFIRM"
                              }]
                            }
                            """.formatted(hunter, hunter);
                });
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
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
        AuditJob job = new AuditJob("dedup123", "java");
        job.workDir(tempDir.resolve("audit_dedup123"));
        Files.createDirectories(job.workDir());

        var result = supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "code_execution_team_general_endpoint_review"),
                Map.of(
                        "code_execution", taskFile("code_execution", 1).toString(),
                        "code_execution_team_general_endpoint_review",
                        taskFile("code_execution_team_general_endpoint_review", 1).toString()
                ),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        // Consolidation across duplicate reports now happens once in
        // IntelligentAuditGraph over the full accumulated multi-round set, not
        // per round here — so both raw findings come back untouched.
        assertThat(result.findings()).hasSize(2);
        assertThat(result.reviewed()).containsExactlyInAnyOrder(
                "code_execution", "code_execution_team_general_endpoint_review");
    }

    @Test
    void capsHunterSessionsToHighestPriorityTasks() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        List<String> invoked = new ArrayList<>();
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    calls.incrementAndGet();
                    Map<String, ClaudeGateway.AgentDef> agents =
                            invocation.getArgument(3);
                    String hunter = agents.keySet().iterator().next();
                    invoked.add(hunter);
                    return """
                            {"selected_hunters":["%s"],"rationale":"ok","findings":[]}
                            """.formatted(hunter);
                });
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(true, 10, 5, 80),
                new JobLogBroker(),
                AuditMemoryService.NOOP,
                Duration.ofSeconds(5),
                Duration.ofSeconds(1)
        );
        AuditJob job = new AuditJob("cap123", "java");
        job.workDir(tempDir.resolve("audit_cap123"));
        Files.createDirectories(job.workDir());
        List<String> candidates = new ArrayList<>();
        Map<String, String> manifest = new LinkedHashMap<>();
        for (int i = 0; i < 30; i++) {
            String hunter = "ssrf_batch_" + i;
            candidates.add(hunter);
            manifest.put(hunter, taskFileWithDecision(hunter, 16, 100 - i)
                    .toString());
        }

        supervisor.runRound(job, Path.of("source"), Map.of(), candidates,
                manifest, Map.of(), Map.of(), Set.of(), Set.of(), Set.of());

        assertThat(calls).hasValue(24);
        assertThat(invoked)
                .contains("ssrf_batch_0", "ssrf_batch_23")
                .doesNotContain("ssrf_batch_24", "ssrf_batch_29");
    }

    @Test
    void reservesSlotsForEachMandatoryCategoryBeforeFillingByPriority()
            throws Exception {
        AtomicInteger calls = new AtomicInteger();
        List<String> invoked = new ArrayList<>();
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    calls.incrementAndGet();
                    Map<String, ClaudeGateway.AgentDef> agents =
                            invocation.getArgument(3);
                    String hunter = agents.keySet().iterator().next();
                    invoked.add(hunter);
                    return """
                            {"selected_hunters":["%s"],"rationale":"ok","findings":[]}
                            """.formatted(hunter);
                });
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(true, 10, 5, 80),
                new JobLogBroker(),
                AuditMemoryService.NOOP,
                Duration.ofSeconds(10),
                // This test asserts selection logic (which hunters get picked),
                // not slot-wait timing — 24 near-instant mock calls still have
                // to clear the semaphore 2-at-a-time, and under full-suite
                // system load a 1s slot timeout was observed to flake even
                // though the mock never blocks. A few seconds of headroom
                // removes that scheduling-noise risk without weakening what
                // the test actually verifies.
                Duration.ofSeconds(5)
        );
        AuditJob job = new AuditJob("mandatory123", "java");
        job.workDir(tempDir.resolve("audit_mandatory123"));
        Files.createDirectories(job.workDir());

        // 25 non-mandatory batches all scored far above the 3 mandatory
        // categories, so a pure global-priority sort would crowd every
        // mandatory category out of the 24-slot cap entirely.
        List<String> candidates = new ArrayList<>();
        Map<String, String> manifest = new LinkedHashMap<>();
        for (int i = 0; i < 25; i++) {
            String hunter = "sql_injection_batch_" + i;
            candidates.add(hunter);
            manifest.put(hunter, taskFileWithDecision(hunter, 16, 200).toString());
        }
        for (String mandatory : List.of("authorization", "code_execution", "ssrf")) {
            candidates.add(mandatory);
            manifest.put(mandatory, taskFileWithDecision(mandatory, 16, 5).toString());
        }

        supervisor.runRound(job, Path.of("source"), Map.of(), candidates,
                manifest, Map.of(), Map.of(), Set.of(), Set.of(), Set.of());

        assertThat(calls).hasValue(24);
        assertThat(invoked).contains("authorization", "code_execution", "ssrf");
    }

    @Test
    void retryableModelSlotFailuresAreDistinctFromTerminalTimeouts()
            throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Thread.sleep(300);
                    Map<String, ClaudeGateway.AgentDef> agents = invocation.getArgument(3);
                    String hunter = agents.keySet().iterator().next();
                    return """
                            {"selected_hunters":["%s"],"rationale":"ok","findings":[]}
                            """.formatted(hunter);
                });
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(true, 10, 5, 80),
                new JobLogBroker(),
                AuditMemoryService.NOOP,
                Duration.ofSeconds(5),
                Duration.ofMillis(50)
        );
        AuditJob job = new AuditJob("slotwait123", "java");
        job.workDir(tempDir.resolve("audit_slotwait123"));
        Files.createDirectories(job.workDir());

        // 3 hunters, only 2 model slots: the 3rd cannot acquire within 50ms
        // and never actually runs, so it must be classified retryable, not a
        // terminal timeout.
        var result = supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("code_execution", "authorization", "ssrf"),
                Map.of(
                        "code_execution", taskFile("code_execution", 1).toString(),
                        "authorization", authorizationTaskFile().toString(),
                        "ssrf", taskFile("ssrf", 1).toString()
                ),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        assertThat(result.reviewed()).hasSize(2);
        assertThat(result.retryableFailures()).hasSize(1);
        assertThat(result.timedOut()).isEmpty();
    }

    @Test
    void timesOutHungHunterSession() throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Thread.sleep(TimeUnit.SECONDS.toMillis(5));
                    return """
                            {"selected_hunters":["ssrf"],"rationale":"late","findings":[]}
                            """;
                });
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(true, 10, 5, 80),
                new JobLogBroker(),
                AuditMemoryService.NOOP,
                Duration.ofMillis(100),
                Duration.ofMillis(50)
        );
        AuditJob job = new AuditJob("timeout123", "java");
        job.workDir(tempDir.resolve("audit_timeout123"));
        Files.createDirectories(job.workDir());

        var result = supervisor.runRound(
                job,
                Path.of("source"),
                Map.of(),
                List.of("ssrf"),
                Map.of("ssrf", taskFile("ssrf", 1).toString()),
                Map.of(),
                Map.of(),
                Set.of(),
                Set.of(),
                Set.of()
        );

        assertThat(result.timedOut()).isEmpty();
        assertThat(result.reviewed()).isEmpty();
        assertThat(result.retryableFailures()).containsExactly("ssrf");
        assertThat(result.rationale()).contains("timed out after");
    }

    @Test
    void hunterSessionTimeoutIsRetryableAcrossResume() throws Exception {
        ClaudeGateway gateway = mock(ClaudeGateway.class);
        when(gateway.supervise(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> {
                    Thread.sleep(TimeUnit.SECONDS.toMillis(5));
                    return """
                            {"selected_hunters":["ssrf"],"rationale":"late","findings":[]}
                            """;
                })
                .thenReturn("""
                        {"selected_hunters":["ssrf"],"rationale":"resumed","findings":[]}
                        """);
        ObjectMapper objectMapper = new ObjectMapper();
        SupervisorAgent supervisor = new SupervisorAgent(
                gateway,
                objectMapper,
                new FindingParser(objectMapper),
                new OrchestratorProperties(true, 10, 5, 80),
                new JobLogBroker(),
                AuditMemoryService.NOOP,
                Duration.ofMillis(100),
                Duration.ofMillis(50)
        );
        AuditJob job = new AuditJob("timeoutretry123", "java");
        job.workDir(tempDir.resolve("audit_timeoutretry123"));
        Files.createDirectories(job.workDir());
        Map<String, String> manifest = Map.of("ssrf", taskFile("ssrf", 1).toString());

        var firstRound = supervisor.runRound(
                job, Path.of("source"), Map.of(), List.of("ssrf"),
                manifest, Map.of(), Map.of(), Set.of(), Set.of(), Set.of()
        );
        assertThat(firstRound.timedOut()).isEmpty();
        assertThat(firstRound.retryableFailures()).containsExactly("ssrf");

        var secondRound = supervisor.runRound(
                job, Path.of("source"), Map.of(), List.of("ssrf"),
                manifest, Map.of(), Map.of(), Set.of(), Set.of(), Set.of("ssrf")
        );
        assertThat(secondRound.reviewed()).containsExactly("ssrf");
        assertThat(secondRound.timedOut()).isEmpty();
        assertThat(secondRound.retryableFailures()).isEmpty();
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

    private Path taskFileWithDecision(
            String hunter,
            int recommendedSteps,
            int priority
    ) throws Exception {
        Path tasks = tempDir.resolve("tasks");
        Files.createDirectories(tasks);
        Path task = tasks.resolve(hunter + "-decision.json");
        Files.writeString(task, """
                {
                  "hunter":"%s",
                  "candidate_count":1,
                  "stored_candidate_count":0,
                  "harness_decision":{
                    "recommended_steps":%d,
                    "priority_score":%d,
                    "rationale":"approved prior"
                  }
                }
                """.formatted(hunter, recommendedSteps, priority));
        return task;
    }

    private Path endpointSurfaceTask(String hunter) throws Exception {
        Path tasks = tempDir.resolve("tasks");
        Files.createDirectories(tasks);
        Path task = tasks.resolve(hunter + "-surface.json");
        Files.writeString(task, """
                {
                  "hunter":"%s",
                  "candidate_count":0,
                  "stored_candidate_count":0,
                  "endpoint_review_surface":[{"path":"/xss/reflect"}]
                }
                """.formatted(hunter));
        return task;
    }

    private Path endpointChunkOnlyTask(String hunter) throws Exception {
        Path tasks = tempDir.resolve("tasks");
        Files.createDirectories(tasks);
        Path chunk = tasks.resolve(hunter + "-endpoint-review-0001.json");
        Files.writeString(chunk, """
                {"start_index":0,"end_index":0,"items":[{"path":"/xss/reflect"}]}
                """);
        Path task = tasks.resolve(hunter + "-chunk-only.json");
        Files.writeString(task, """
                {
                  "hunter":"%s",
                  "candidate_count":0,
                  "stored_candidate_count":0,
                  "endpoint_review_count":1,
                  "endpoint_review_chunks":["%s"]
                }
                """.formatted(hunter, chunk.toAbsolutePath().normalize()));
        return task;
    }
}
