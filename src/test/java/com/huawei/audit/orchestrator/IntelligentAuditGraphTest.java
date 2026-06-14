package com.huawei.audit.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.huawei.audit.agent.EvidencePreparationService;
import com.huawei.audit.agent.SubagentDefinitionService;
import com.huawei.audit.agent.SupervisorAgent;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.JobLogBroker;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

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
        when(supervisor.run(any(), any(), any(), any(), any(), any())).thenReturn(
                new SupervisorAgent.SupervisorResult(
                        List.of("sql_injection", "ssrf"),
                        "delegated two native subagents",
                        List.of(
                                finding("sqli-1", "SQL_INJECTION", 10),
                                finding("ssrf-1", "SSRF", 20)
                        )
                )
        );

        IntelligentAuditGraph graph = new IntelligentAuditGraph(
                evidence,
                definitions,
                supervisor,
                new FindingDeduplicator(),
                new AttackChainCorrelator(),
                new JobLogBroker()
        );

        OrchestratorAgentState result = graph.invoke(
                job,
                Path.of("source"),
                Map.of("primary_language", "java"),
                List.of("sql_injection", "ssrf")
        );

        assertThat(result.finalFindings()).hasSize(2);
        assertThat(result.taskSummary())
                .containsEntry("total_hunters", 2)
                .containsEntry("claude_code_processes", 1)
                .containsKey("analysis_coverage")
                .containsEntry(
                        "subagent_mode",
                        "native-claude-code-agent-tool"
                );
    }

    private Map<String, Object> finding(String ruleId, String type, int line) {
        return Map.of(
                "rule_id", ruleId,
                "vuln_type", type,
                "severity", "HIGH",
                "confidence", 0.9,
                "file_path", "src/Test.java",
                "start_line", line
        );
    }

}
