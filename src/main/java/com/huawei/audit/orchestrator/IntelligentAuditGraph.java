package com.huawei.audit.orchestrator;

import com.huawei.audit.agent.EvidencePreparationService;
import com.huawei.audit.agent.SubagentDefinitionService;
import com.huawei.audit.agent.SupervisorAgent;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.memory.AuditMemoryService;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class IntelligentAuditGraph {
    private final EvidencePreparationService evidencePreparation;
    private final SubagentDefinitionService subagentDefinitions;
    private final SupervisorAgent supervisor;
    private final FindingDeduplicator deduplicator;
    private final AttackChainCorrelator chainCorrelator;
    private final AuditMemoryService auditMemory;
    private final JobLogBroker logs;

    public IntelligentAuditGraph(
            EvidencePreparationService evidencePreparation,
            SubagentDefinitionService subagentDefinitions,
            SupervisorAgent supervisor,
            FindingDeduplicator deduplicator,
            AttackChainCorrelator chainCorrelator,
            AuditMemoryService auditMemory,
            JobLogBroker logs
    ) {
        this.evidencePreparation = evidencePreparation;
        this.subagentDefinitions = subagentDefinitions;
        this.supervisor = supervisor;
        this.deduplicator = deduplicator;
        this.chainCorrelator = chainCorrelator;
        this.auditMemory = auditMemory;
        this.logs = logs;
    }

    public AuditResult invoke(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates
    ) throws Exception {
        logs.publish(job,
                "[orchestrator] preparing HTTP interface inventory for AgentScope subagents");

        @SuppressWarnings("unchecked")
        List<Map<String, String>> dependencies = (List<Map<String, String>>)
                techProfile.getOrDefault("dependencies", List.of());
        var preparation = evidencePreparation.prepare(
                job, sourceRoot, candidates, dependencies);
        Map<String, String> skillNames = subagentDefinitions.materialize(
                job.workDir(), preparation.expandedCandidates(), preparation.manifest());

        var result = supervisor.run(
                job, sourceRoot, techProfile,
                preparation.expandedCandidates(),
                preparation.manifest(),
                skillNames,
                preparation.analysisSummary());

        List<Map<String, Object>> deduped = deduplicator.deduplicate(result.findings());
        String appPackage = String.valueOf(
                techProfile.getOrDefault("app_package", ""));
        List<Map<String, Object>> chains = chainCorrelator.correlate(deduped, appPackage);

        List<Map<String, Object>> finalFindings = new ArrayList<>(deduped);
        finalFindings.addAll(chains);
        auditMemory.rememberFindings(job, sourceRoot, techProfile, finalFindings);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("candidate_hunters", candidates);
        summary.put("delegated_hunters", result.selectedHunters());
        summary.put("total_hunters", result.selectedHunters().size());
        summary.put("total_raw", result.findings().size());
        summary.put("after_dedup", deduped.size());
        summary.put("chain_findings", chains.size());
        summary.put("final", finalFindings.size());
        summary.put("by_status", Map.of("done", result.selectedHunters().size()));
        summary.put("supervisor_rationale", result.rationale());
        summary.put("agentscope_sessions", 1);
        summary.put("subagent_mode", "agentscope-java-harness-subagents");
        summary.put("scan_strategy", "candidate-path-whitebox");
        summary.put("analysis_coverage", preparation.analysisSummary());

        return new AuditResult(
                finalFindings,
                deduplicator.statistics(finalFindings),
                summary);
    }

    public record AuditResult(
            List<Map<String, Object>> finalFindings,
            Map<String, Object> stats,
            Map<String, Object> taskSummary
    ) { }
}
