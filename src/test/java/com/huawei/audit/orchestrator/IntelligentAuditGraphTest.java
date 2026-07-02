package com.huawei.audit.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.agent.EvidencePreparationService;
import com.huawei.audit.agent.FindingConsolidator;
import com.huawei.audit.agent.SubagentDefinitionService;
import com.huawei.audit.agent.SupervisorAgent;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.domain.JobStatus;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.memory.AuditMemoryService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class IntelligentAuditGraphTest {

    @Test
    void preparesEvidenceRunsOneSupervisorAndFinalizesState() throws Exception {
        EvidencePreparationService evidence = mock(EvidencePreparationService.class);
        SubagentDefinitionService definitions = mock(SubagentDefinitionService.class);
        SupervisorAgent supervisor = mock(SupervisorAgent.class);
        AuditJob job = new AuditJob("graph123", "java");
        job.workDir(Path.of("workspace", "audit_graph123"));

        when(evidence.prepare(any(), any(), any(), any())).thenReturn(
                new EvidencePreparationService.PreparationResult(
                        Map.of(
                                "sql_injection", "evidence/sql_injection.json",
                                "ssrf", "evidence/ssrf.json"
                        ),
                        Map.of("candidate_paths", 2),
                        List.of("sql_injection", "ssrf")
                )
        );
        when(definitions.materialize(any(), any(), any())).thenReturn(
                Map.of("sql_injection", "audit-sql-injection",
                       "ssrf", "audit-ssrf")
        );
        when(supervisor.runRound(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any()
        )).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(
                                finding("sqli-1", "SQL_INJECTION", 10),
                                finding("ssrf-1", "SSRF", 20)
                        ),
                        List.of("sql_injection", "ssrf"),
                        List.of(),
                        List.of(),
                        "delegated two native subagents"
                )
        );

        IntelligentAuditGraph graph = newGraph(evidence, definitions, supervisor,
                AuditMemoryService.NOOP);

        IntelligentAuditGraph.AuditResult result = graph.invoke(
                job,
                Path.of("source"),
                Map.of("primary_language", "java"),
                List.of("sql_injection", "ssrf")
        );

        assertThat(result.finalFindings()).hasSize(2);
        assertThat(result.taskSummary())
                .containsEntry("total_hunters", 2)
                .containsEntry("agentscope_sessions", 1)
                .containsEntry("rounds", 1)
                .containsEntry("ceiling_hit", false)
                .containsKey("analysis_coverage")
                .containsEntry(
                        "subagent_mode",
                        "agentscope-java-harness-subagents"
                );
        assertThat(job.roundsCompleted()).isEqualTo(1);
        assertThat(job.continuationComplete()).isTrue();
    }

    @Test
    void multiRoundLoopAccumulatesFindingsAcrossRetries() throws Exception {
        EvidencePreparationService evidence = mock(EvidencePreparationService.class);
        SubagentDefinitionService definitions = mock(SubagentDefinitionService.class);
        SupervisorAgent supervisor = mock(SupervisorAgent.class);
        AuditJob job = new AuditJob("multi123", "java");
        job.workDir(Path.of("workspace", "audit_multi123"));

        when(evidence.prepare(any(), any(), any(), any())).thenReturn(
                new EvidencePreparationService.PreparationResult(
                        Map.of("sql_injection", "evidence/sql_injection.json",
                               "ssrf", "evidence/ssrf.json"),
                        Map.of(),
                        List.of("sql_injection", "ssrf")
                )
        );
        when(definitions.materialize(any(), any(), any())).thenReturn(Map.of());

        when(supervisor.runRound(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any()
        )).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(finding("sqli-1", "SQL_INJECTION", 10)),
                        List.of("sql_injection"),
                        List.of(),
                        List.of("ssrf"),
                        "round 1: ssrf could not get a model slot in time"
                )
        ).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(finding("ssrf-1", "SSRF", 20)),
                        List.of("ssrf"),
                        List.of(),
                        List.of(),
                        "round 2: ssrf completed"
                )
        );

        IntelligentAuditGraph graph = newGraph(evidence, definitions, supervisor,
                AuditMemoryService.NOOP);

        IntelligentAuditGraph.AuditResult result = graph.invoke(
                job, Path.of("source"), Map.of(), List.of("sql_injection", "ssrf"));

        assertThat(result.finalFindings()).hasSize(2);
        assertThat(job.roundsCompleted()).isEqualTo(2);
        assertThat(job.continuationComplete()).isTrue();
        assertThat(job.ceilingHit()).isFalse();
        verify(supervisor, times(2)).runRound(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void consolidatesBeforeDeduplicatingAcrossRounds() throws Exception {
        EvidencePreparationService evidence = mock(EvidencePreparationService.class);
        SubagentDefinitionService definitions = mock(SubagentDefinitionService.class);
        SupervisorAgent supervisor = mock(SupervisorAgent.class);
        AuditJob job = new AuditJob("consolidate123", "java");
        job.workDir(Path.of("workspace", "audit_consolidate123"));

        when(evidence.prepare(any(), any(), any(), any())).thenReturn(
                new EvidencePreparationService.PreparationResult(
                        Map.of("code_execution", "evidence/code_execution.json",
                               "code_execution_team_review", "evidence/team_review.json"),
                        Map.of(),
                        List.of("code_execution", "code_execution_team_review")
                )
        );
        when(definitions.materialize(any(), any(), any())).thenReturn(Map.of());

        // Two different rule_ids, same vuln_type + http_path, reported from
        // two DIFFERENT rounds. FindingDeduplicator keys on rule_id/file_path/
        // start_line alone, so without a prior cross-round consolidation pass
        // these would survive as two separate findings.
        Map<String, Object> roundOneFinding = finding("cmdinj-1", "COMMAND_INJECTION", 0);
        roundOneFinding.put("http_path", "/rce/exec");
        roundOneFinding.put("severity", "MEDIUM");
        Map<String, Object> roundTwoFinding = finding("cmdinj-2", "COMMAND_INJECTION", 0);
        roundTwoFinding.put("http_path", "/rce/exec");
        roundTwoFinding.put("severity", "CRITICAL");

        when(supervisor.runRound(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any()
        )).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(roundOneFinding), List.of("code_execution"),
                        List.of(), List.of(), "round 1"
                )
        ).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(roundTwoFinding), List.of("code_execution_team_review"),
                        List.of(), List.of(), "round 2"
                )
        );

        IntelligentAuditGraph graph = newGraph(evidence, definitions, supervisor,
                AuditMemoryService.NOOP);

        IntelligentAuditGraph.AuditResult result = graph.invoke(
                job, Path.of("source"), Map.of(),
                List.of("code_execution", "code_execution_team_review"));

        assertThat(result.finalFindings()).singleElement().satisfies(f ->
                assertThat(f).containsEntry("merged_count", 2));
    }

    @Test
    void rememberFindingsCalledExactlyOnceAcrossMultipleRounds() throws Exception {
        EvidencePreparationService evidence = mock(EvidencePreparationService.class);
        SubagentDefinitionService definitions = mock(SubagentDefinitionService.class);
        SupervisorAgent supervisor = mock(SupervisorAgent.class);
        AuditMemoryService memory = mock(AuditMemoryService.class);
        AuditJob job = new AuditJob("remember123", "java");
        job.workDir(Path.of("workspace", "audit_remember123"));

        when(evidence.prepare(any(), any(), any(), any())).thenReturn(
                new EvidencePreparationService.PreparationResult(
                        Map.of("sql_injection", "evidence/sql_injection.json",
                               "ssrf", "evidence/ssrf.json"),
                        Map.of(),
                        List.of("sql_injection", "ssrf")
                )
        );
        when(definitions.materialize(any(), any(), any())).thenReturn(Map.of());
        when(supervisor.runRound(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any()
        )).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(), List.of("sql_injection"), List.of(), List.of("ssrf"), "r1")
        ).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(), List.of("ssrf"), List.of(), List.of(), "r2")
        );

        IntelligentAuditGraph graph = newGraph(evidence, definitions, supervisor, memory);
        graph.invoke(job, Path.of("source"), Map.of(), List.of("sql_injection", "ssrf"));

        verify(memory, times(1)).rememberFindings(any(), any(), any(), any());
    }

    @Test
    void continuesPastConfiguredRoundCeilingUntilReviewed(@TempDir Path tempDir)
            throws Exception {
        EvidencePreparationService evidence = mock(EvidencePreparationService.class);
        SubagentDefinitionService definitions = mock(SubagentDefinitionService.class);
        SupervisorAgent supervisor = mock(SupervisorAgent.class);
        AuditJob job = new AuditJob("ceiling123", "java");
        job.workDir(tempDir);

        when(evidence.prepare(any(), any(), any(), any())).thenReturn(
                new EvidencePreparationService.PreparationResult(
                        Map.of("ssrf", "evidence/ssrf.json"),
                        Map.of(),
                        List.of("ssrf")
                )
        );
        when(definitions.materialize(any(), any(), any())).thenReturn(Map.of());
        when(supervisor.runRound(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any()
        ))
                .thenReturn(new SupervisorAgent.RoundResult(
                        List.of(), List.of(), List.of(), List.of("ssrf"), "retry 1"))
                .thenReturn(new SupervisorAgent.RoundResult(
                        List.of(), List.of(), List.of(), List.of("ssrf"), "retry 2"))
                .thenReturn(new SupervisorAgent.RoundResult(
                        List.of(), List.of(), List.of(), List.of("ssrf"), "retry 3"))
                .thenReturn(new SupervisorAgent.RoundResult(
                        List.of(), List.of(), List.of(), List.of("ssrf"), "retry 4"))
                .thenReturn(new SupervisorAgent.RoundResult(
                        List.of(), List.of(), List.of(), List.of("ssrf"), "retry 5"))
                .thenReturn(new SupervisorAgent.RoundResult(
                        List.of(), List.of(), List.of(), List.of("ssrf"), "retry 6"))
                .thenReturn(new SupervisorAgent.RoundResult(
                        List.of(), List.of("ssrf"), List.of(), List.of(), "reviewed"));

        IntelligentAuditGraph graph = newGraph(evidence, definitions, supervisor,
                AuditMemoryService.NOOP);

        IntelligentAuditGraph.AuditResult result = graph.invoke(
                job, Path.of("source"), Map.of(), List.of("ssrf"));

        assertThat(job.ceilingHit()).isFalse();
        assertThat(job.continuationComplete()).isTrue();
        assertThat(job.status()).isEqualTo(JobStatus.DONE);
        assertThat(result.taskSummary()).containsEntry("ceiling_hit", false);
        assertThat(job.roundsCompleted()).isEqualTo(7);
    }

    @Test
    void resumeSeedsFromRawFindingsLogNotFromConsolidatedJobFindings(
            @TempDir Path tempDir
    ) throws Exception {
        EvidencePreparationService evidence = mock(EvidencePreparationService.class);
        SubagentDefinitionService definitions = mock(SubagentDefinitionService.class);
        SupervisorAgent supervisor = mock(SupervisorAgent.class);
        AuditJob job = new AuditJob("resumeseed123", "java");
        job.workDir(tempDir);

        when(evidence.prepare(any(), any(), any(), any())).thenReturn(
                new EvidencePreparationService.PreparationResult(
                        Map.of("code_execution", "evidence/code_execution.json"),
                        Map.of(),
                        List.of("code_execution")
                )
        );
        when(definitions.materialize(any(), any(), any())).thenReturn(Map.of());

        // Simulate a prior round's TRUE raw output already durable on disk
        // (what appendRawFindings would have written before a crash).
        Map<String, Object> priorRoundRaw = finding("cmdinj-1", "COMMAND_INJECTION", 0);
        priorRoundRaw.put("http_path", "/rce/exec");
        priorRoundRaw.put("severity", "MEDIUM");
        Files.writeString(tempDir.resolve("raw-round-findings.jsonl"),
                new ObjectMapper().writeValueAsString(priorRoundRaw) + "\n");

        // job.findings() deliberately holds an unrelated stale sentinel value
        // — proving the resumed round does NOT reuse this already-
        // consolidated view as a raw seed.
        job.findings(List.of(Map.of("rule_id", "stale-should-not-be-reused")));

        Map<String, Object> newRoundRaw = finding("cmdinj-2", "COMMAND_INJECTION", 0);
        newRoundRaw.put("http_path", "/rce/exec");
        newRoundRaw.put("severity", "CRITICAL");
        when(supervisor.runRound(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any()
        )).thenReturn(
                new SupervisorAgent.RoundResult(
                        List.of(newRoundRaw), List.of("code_execution"),
                        List.of(), List.of(), "resumed round")
        );

        IntelligentAuditGraph graph = newGraph(evidence, definitions, supervisor,
                AuditMemoryService.NOOP);
        IntelligentAuditGraph.AuditResult result = graph.invokeResumed(
                job, Path.of("source"), Map.of(), List.of("code_execution"),
                Set.of(), Set.of(), Set.of());

        assertThat(result.finalFindings()).singleElement().satisfies(f -> {
            assertThat(f).containsEntry("merged_count", 2);
            String message = String.valueOf(f.get("message"));
            long mergedMentions = message.split("Merged", -1).length - 1;
            assertThat(mergedMentions)
                    .as("'Merged N duplicate reports' must appear exactly once, "
                            + "not compound across the resume boundary: %s", message)
                    .isEqualTo(1);
        });
        assertThat(result.finalFindings().toString())
                .doesNotContain("stale-should-not-be-reused");
    }

    private IntelligentAuditGraph newGraph(
            EvidencePreparationService evidence,
            SubagentDefinitionService definitions,
            SupervisorAgent supervisor,
            AuditMemoryService memory
    ) {
        return new IntelligentAuditGraph(
                evidence,
                definitions,
                supervisor,
                new FindingConsolidator(),
                new FindingDeduplicator(),
                new AttackChainCorrelator(),
                memory,
                new JobLogBroker(),
                new ObjectMapper(),
                new OrchestratorProperties(true, 10, 5, 80)
        );
    }

    private Map<String, Object> finding(String ruleId, String type, int line) {
        var map = new java.util.LinkedHashMap<String, Object>();
        map.put("rule_id", ruleId);
        map.put("vuln_type", type);
        map.put("severity", "HIGH");
        map.put("confidence", 0.9);
        map.put("file_path", "src/Test.java");
        map.put("start_line", line);
        return map;
    }

}
