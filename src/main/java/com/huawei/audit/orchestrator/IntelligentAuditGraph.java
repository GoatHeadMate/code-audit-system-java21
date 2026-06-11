package com.huawei.audit.orchestrator;

import static org.bsc.langgraph4j.GraphDefinition.END;
import static org.bsc.langgraph4j.GraphDefinition.START;
import static org.bsc.langgraph4j.action.AsyncNodeAction.node_async;

import com.huawei.audit.agent.EvidencePreparationService;
import com.huawei.audit.agent.SubagentDefinitionService;
import com.huawei.audit.agent.SupervisorAgent;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.JobLogBroker;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.UUID;
import org.bsc.langgraph4j.CompiledGraph;
import org.bsc.langgraph4j.StateGraph;
import org.springframework.stereotype.Component;

@Component
public class IntelligentAuditGraph {
    private static final String PREPARE = "prepare_evidence";
    private static final String SUPERVISE = "run_supervisor";
    private static final String FINALIZE = "finalize";

    private final EvidencePreparationService evidencePreparation;
    private final SubagentDefinitionService subagentDefinitions;
    private final SupervisorAgent supervisor;
    private final FindingDeduplicator deduplicator;
    private final AttackChainCorrelator chainCorrelator;
    private final JobLogBroker logs;
    private final ConcurrentHashMap<String, ExecutionContext> contexts =
            new ConcurrentHashMap<>();
    private final CompiledGraph<OrchestratorAgentState> graph;

    public IntelligentAuditGraph(
            EvidencePreparationService evidencePreparation,
            SubagentDefinitionService subagentDefinitions,
            SupervisorAgent supervisor,
            FindingDeduplicator deduplicator,
            AttackChainCorrelator chainCorrelator,
            JobLogBroker logs
    ) {
        this.evidencePreparation = evidencePreparation;
        this.subagentDefinitions = subagentDefinitions;
        this.supervisor = supervisor;
        this.deduplicator = deduplicator;
        this.chainCorrelator = chainCorrelator;
        this.logs = logs;
        this.graph = buildGraph();
    }

    public OrchestratorAgentState invoke(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates
    ) {
        String contextId = UUID.randomUUID().toString();
        contexts.put(
                contextId,
                new ExecutionContext(job, sourceRoot, techProfile)
        );
        try {
            Map<String, Object> initialState = Map.of(
                    "context_id", contextId,
                    "candidates", candidates,
                    "raw_findings", List.of()
            );
            return graph.invoke(initialState).orElseThrow(
                    () -> new IllegalStateException("LangGraph4j returned no final state")
            );
        } finally {
            contexts.remove(contextId);
        }
    }

    private CompiledGraph<OrchestratorAgentState> buildGraph() {
        try {
            return new StateGraph<OrchestratorAgentState>(OrchestratorAgentState::new)
                    .addNode(PREPARE, node_async(this::prepareEvidence))
                    .addNode(SUPERVISE, node_async(this::runSupervisor))
                    .addNode(FINALIZE, node_async(this::finalizeFindings))
                    .addEdge(START, PREPARE)
                    .addEdge(PREPARE, SUPERVISE)
                    .addEdge(SUPERVISE, FINALIZE)
                    .addEdge(FINALIZE, END)
                    .compile();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to compile LangGraph4j workflow", exception);
        }
    }

    private Map<String, Object> prepareEvidence(OrchestratorAgentState state)
            throws Exception {
        ExecutionContext context = context(state);
        logs.publish(
                context.job(),
                "[langgraph4j] preparing HTTP interface inventory for native subagents"
        );
        subagentDefinitions.materialize(
                context.job().workDir(),
                state.candidates()
        );
        var preparation = evidencePreparation.prepare(
                context.job(),
                context.sourceRoot(),
                state.candidates()
        );
        return Map.of(
                "evidence_manifest", preparation.manifest(),
                "analysis_summary", preparation.analysisSummary()
        );
    }

    private Map<String, Object> runSupervisor(OrchestratorAgentState state)
            throws Exception {
        ExecutionContext context = context(state);
        var result = supervisor.run(
                context.job(),
                context.sourceRoot(),
                context.techProfile(),
                state.candidates(),
                state.evidenceManifest()
        );
        return Map.of(
                "delegated_hunters", result.selectedHunters(),
                "supervisor_rationale", result.rationale(),
                "raw_findings", result.findings()
        );
    }

    private Map<String, Object> finalizeFindings(OrchestratorAgentState state) {
        ExecutionContext context = context(state);
        List<Map<String, Object>> deduped = deduplicator.deduplicate(
                state.rawFindings()
        );
        String appPackage = String.valueOf(
                context.techProfile().getOrDefault("app_package", "")
        );
        List<Map<String, Object>> chains = chainCorrelator.correlate(
                deduped,
                appPackage
        );
        List<Map<String, Object>> finalFindings = new ArrayList<>(deduped);
        finalFindings.addAll(chains);

        Map<String, Object> summary = new java.util.LinkedHashMap<>();
        summary.put("candidate_hunters", state.candidates());
        summary.put("delegated_hunters", state.primaryHunters());
        summary.put("total_hunters", state.primaryHunters().size());
        summary.put("total_raw", state.rawFindings().size());
        summary.put("after_dedup", deduped.size());
        summary.put("chain_findings", chains.size());
        summary.put("final", finalFindings.size());
        summary.put("by_status", Map.of("done", state.primaryHunters().size()));
        summary.put(
                "supervisor_rationale",
                state.value("supervisor_rationale", "")
        );
        summary.put("claude_code_processes", 1);
        summary.put("subagent_mode", "native-claude-code-agent-tool");
        summary.put("scan_strategy", "candidate-path-whitebox");
        summary.put("codeql_used", false);
        summary.put("analysis_coverage", state.analysisSummary());
        return Map.of(
                "final_findings", finalFindings,
                "stats", deduplicator.statistics(finalFindings),
                "task_summary", summary
        );
    }

    private ExecutionContext context(OrchestratorAgentState state) {
        ExecutionContext context = contexts.get(state.contextId());
        if (context == null) {
            throw new IllegalStateException(
                    "Missing execution context: " + state.contextId()
            );
        }
        return context;
    }

    private record ExecutionContext(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile
    ) { }
}
