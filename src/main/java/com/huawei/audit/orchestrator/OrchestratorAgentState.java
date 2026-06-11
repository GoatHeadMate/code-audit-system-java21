package com.huawei.audit.orchestrator;

import java.util.List;
import java.util.Map;
import org.bsc.langgraph4j.state.AgentState;

public final class OrchestratorAgentState extends AgentState {
    public OrchestratorAgentState(Map<String, Object> data) {
        super(data);
    }

    public String contextId() {
        return (String) value("context_id").orElseThrow();
    }

    @SuppressWarnings("unchecked")
    public List<String> candidates() {
        return value("candidates", List.of());
    }

    @SuppressWarnings("unchecked")
    public List<String> primaryHunters() {
        return value("delegated_hunters", List.of());
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> evidenceManifest() {
        return value("evidence_manifest", Map.of());
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> analysisSummary() {
        return value("analysis_summary", Map.of());
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> rawFindings() {
        return value("raw_findings", List.of());
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> finalFindings() {
        return value("final_findings", List.of());
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> stats() {
        return value("stats", Map.of());
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> taskSummary() {
        return value("task_summary", Map.of());
    }
}
