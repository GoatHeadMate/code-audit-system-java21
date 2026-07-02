package com.huawei.audit.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.agent.EvidencePreparationService;
import com.huawei.audit.agent.FindingConsolidator;
import com.huawei.audit.agent.SubagentDefinitionService;
import com.huawei.audit.agent.SupervisorAgent;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.JobLogBroker;
import com.huawei.audit.memory.AuditMemoryService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class IntelligentAuditGraph {
    private final EvidencePreparationService evidencePreparation;
    private final SubagentDefinitionService subagentDefinitions;
    private final SupervisorAgent supervisor;
    private final FindingConsolidator findingConsolidator;
    private final FindingDeduplicator deduplicator;
    private final AttackChainCorrelator chainCorrelator;
    private final AuditMemoryService auditMemory;
    private final JobLogBroker logs;
    private final ObjectMapper objectMapper;
    private final OrchestratorProperties properties;

    public IntelligentAuditGraph(
            EvidencePreparationService evidencePreparation,
            SubagentDefinitionService subagentDefinitions,
            SupervisorAgent supervisor,
            FindingConsolidator findingConsolidator,
            FindingDeduplicator deduplicator,
            AttackChainCorrelator chainCorrelator,
            AuditMemoryService auditMemory,
            JobLogBroker logs,
            ObjectMapper objectMapper,
            OrchestratorProperties properties
    ) {
        this.evidencePreparation = evidencePreparation;
        this.subagentDefinitions = subagentDefinitions;
        this.supervisor = supervisor;
        this.findingConsolidator = findingConsolidator;
        this.deduplicator = deduplicator;
        this.chainCorrelator = chainCorrelator;
        this.auditMemory = auditMemory;
        this.logs = logs;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    public AuditResult invoke(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates
    ) throws Exception {
        logs.publish(job,
                "[orchestrator] preparing HTTP interface inventory for AgentScope subagents");

        var preparation = prepareEvidence(job, sourceRoot, techProfile, candidates);
        Map<String, String> skillNames = subagentDefinitions.materialize(
                job.workDir(), preparation.expandedCandidates(), preparation.manifest());
        job.totalCandidateCount(preparation.expandedCandidates().size());

        return runRoundLoop(
                job, sourceRoot, techProfile, candidates, preparation, skillNames,
                new ArrayList<>(), new LinkedHashSet<>(), new LinkedHashSet<>(),
                new LinkedHashSet<>(), 0
        );
    }

    public AuditResult invokeResumed(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates,
            Set<String> alreadyReviewed,
            Set<String> alreadyTimedOut,
            Set<String> alreadyFailed
    ) throws Exception {
        logs.publish(job, "[orchestrator] resuming audit; re-deriving evidence manifest");

        var preparation = prepareEvidence(job, sourceRoot, techProfile, candidates);
        Map<String, String> skillNames = subagentDefinitions.materialize(
                job.workDir(), preparation.expandedCandidates(), preparation.manifest());
        job.totalCandidateCount(preparation.expandedCandidates().size());

        // Seed from the raw per-round findings log, NOT job.findings() — the
        // latter is already-consolidated/deduped/chain-correlated pipeline
        // OUTPUT. Feeding that back into the same pipeline as if it were raw
        // input double-processes it: merge counts undercount (an already-
        // merged blob counts as one "variant" instead of its real N), the
        // "Merged N duplicate reports" message suffix compounds on repeat,
        // and previously-derived ATTACK_CHAIN entries risk being re-mined for
        // chains. The raw log is exactly what each round's hunters actually
        // returned, so replaying it reproduces the pre-crash state exactly
        // and the pipeline still runs over the true raw union exactly once.
        List<Map<String, Object>> seedRaw = loadRawFindings(job);
        return runRoundLoop(
                job, sourceRoot, techProfile, candidates, preparation, skillNames,
                seedRaw, new LinkedHashSet<>(alreadyReviewed),
                new LinkedHashSet<>(), new LinkedHashSet<>(alreadyFailed),
                job.roundsCompleted()
        );
    }

    @SuppressWarnings("unchecked")
    private EvidencePreparationService.PreparationResult prepareEvidence(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates
    ) throws Exception {
        List<Map<String, String>> dependencies = (List<Map<String, String>>)
                techProfile.getOrDefault("dependencies", List.of());
        return evidencePreparation.prepare(job, sourceRoot, candidates, dependencies);
    }

    private AuditResult runRoundLoop(
            AuditJob job,
            Path sourceRoot,
            Map<String, Object> techProfile,
            List<String> candidates,
            EvidencePreparationService.PreparationResult preparation,
            Map<String, String> skillNames,
            List<Map<String, Object>> accumulatedRaw,
            Set<String> reviewed,
            Set<String> timedOut,
            Set<String> retryableFailed,
            int startingRound
    ) throws Exception {
        int round = startingRound;
        List<Map<String, Object>> finalFindings = List.of();
        List<Map<String, Object>> deduped = List.of();
        List<Map<String, Object>> chains = List.of();
        String lastRationale = "";

        while (true) {
            round++;
            SupervisorAgent.RoundResult roundResult = supervisor.runRound(
                    job, sourceRoot, techProfile,
                    preparation.expandedCandidates(), preparation.manifest(), skillNames,
                    preparation.analysisSummary(),
                    reviewed, timedOut, retryableFailed
            );
            accumulatedRaw.addAll(roundResult.findings());
            appendRawFindings(job, roundResult.findings());
            reviewed.addAll(roundResult.reviewed());
            retryableFailed.clear();
            retryableFailed.addAll(roundResult.retryableFailures());
            lastRationale = roundResult.rationale();

            List<Map<String, Object>> consolidated = findingConsolidator.consolidate(accumulatedRaw);
            deduped = deduplicator.deduplicate(consolidated);
            String appPackage = String.valueOf(techProfile.getOrDefault("app_package", ""));
            chains = chainCorrelator.correlate(deduped, appPackage);
            finalFindings = new ArrayList<>(deduped);
            finalFindings.addAll(chains);

            boolean fullyDrained = reviewed.size() >= preparation.expandedCandidates().size();
            boolean moreRoundsRemain = !fullyDrained;

            job.mergeRoundOutcome(
                    round, finalFindings,
                    Set.copyOf(roundResult.reviewed()),
                    Set.of(),
                    Set.copyOf(roundResult.retryableFailures()),
                    moreRoundsRemain, false
            );
            persistProgress(job, round, preparation.expandedCandidates().size(),
                    reviewed, Set.of(), retryableFailed, !moreRoundsRemain, false);
            persistFindings(job, finalFindings);

            int remainingCount = Math.max(0,
                    preparation.expandedCandidates().size() - reviewed.size());
            logs.publish(job, "[orchestrator] round " + round + " complete; reviewed="
                    + reviewed.size() + " timedOut=" + timedOut.size()
                    + " retryable=" + retryableFailed.size() + " remaining=" + remainingCount
                    + " findings=" + finalFindings.size());

            if (!moreRoundsRemain) {
                break;
            }
        }

        Map<String, Object> summary = buildTaskSummary(
                candidates, reviewed, timedOut, retryableFailed, accumulatedRaw.size(),
                deduped, chains, finalFindings, lastRationale, preparation, round,
                false
        );
        auditMemory.rememberFindings(job, sourceRoot, techProfile, finalFindings);
        return new AuditResult(finalFindings, deduplicator.statistics(finalFindings), summary);
    }

    private void persistProgress(
            AuditJob job,
            int round,
            int totalCandidates,
            Set<String> reviewed,
            Set<String> timedOut,
            Set<String> retryableFailed,
            boolean complete,
            boolean ceilingHit
    ) {
        try {
            Map<String, Object> progress = new LinkedHashMap<>();
            progress.put("round", round);
            progress.put("total_candidates", totalCandidates);
            progress.put("reviewed", List.copyOf(reviewed));
            progress.put("timed_out", List.copyOf(timedOut));
            progress.put("failed_retryable", List.copyOf(retryableFailed));
            progress.put("complete", complete);
            progress.put("ceiling_hit", ceilingHit);
            progress.put("updated_at", Instant.now().toString());
            Files.writeString(
                    job.workDir().resolve("audit-progress.json"),
                    objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(progress)
            );
        } catch (Exception exception) {
            logs.publish(job, "[orchestrator] failed to persist audit-progress.json: "
                    + exception.getMessage());
        }
    }

    /**
     * Appends this round's raw hunter output, one JSON line per finding, to
     * workDir/raw-round-findings.jsonl. This is the durable record of exactly
     * what hunters returned, kept separate from findings.json (which holds
     * consolidated/deduped/chain-correlated pipeline OUTPUT) so a resumed
     * session can replay the true raw union instead of re-processing already
     * -processed data. Append-only: survives a crash mid-round for every
     * round that completed before it.
     */
    private void appendRawFindings(AuditJob job, List<Map<String, Object>> roundFindings) {
        if (roundFindings.isEmpty()) {
            return;
        }
        try {
            StringBuilder lines = new StringBuilder();
            for (Map<String, Object> finding : roundFindings) {
                lines.append(objectMapper.writeValueAsString(finding)).append('\n');
            }
            Files.writeString(
                    job.workDir().resolve("raw-round-findings.jsonl"),
                    lines.toString(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND
            );
        } catch (Exception exception) {
            logs.publish(job, "[orchestrator] failed to append raw-round-findings.jsonl: "
                    + exception.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> loadRawFindings(AuditJob job) {
        Path rawFile = job.workDir().resolve("raw-round-findings.jsonl");
        List<Map<String, Object>> findings = new ArrayList<>();
        if (!Files.isRegularFile(rawFile)) {
            return findings;
        }
        try {
            for (String line : Files.readAllLines(rawFile)) {
                if (!line.isBlank()) {
                    findings.add(objectMapper.readValue(line, Map.class));
                }
            }
        } catch (Exception exception) {
            logs.publish(job, "[orchestrator] failed to read raw-round-findings.jsonl: "
                    + exception.getMessage());
        }
        return findings;
    }

    private void persistFindings(AuditJob job, List<Map<String, Object>> findings) {
        try {
            Files.writeString(
                    job.workDir().resolve("findings.json"),
                    objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(findings)
            );
        } catch (Exception exception) {
            logs.publish(job, "[orchestrator] failed to persist findings.json: "
                    + exception.getMessage());
        }
    }

    private Map<String, Object> buildTaskSummary(
            List<String> candidates,
            Set<String> reviewed,
            Set<String> timedOut,
            Set<String> retryableFailed,
            int totalRaw,
            List<Map<String, Object>> deduped,
            List<Map<String, Object>> chains,
            List<Map<String, Object>> finalFindings,
            String rationale,
            EvidencePreparationService.PreparationResult preparation,
            int rounds,
            boolean ceilingHit
    ) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("candidate_hunters", candidates);
        summary.put("delegated_hunters", List.copyOf(reviewed));
        summary.put("total_hunters", reviewed.size());
        summary.put("total_raw", totalRaw);
        summary.put("after_dedup", deduped.size());
        summary.put("chain_findings", chains.size());
        summary.put("final", finalFindings.size());
        summary.put("by_status", Map.of(
                "reviewed", reviewed.size(),
                "timed_out", timedOut.size(),
                "retryable_pending", retryableFailed.size()
        ));
        summary.put("supervisor_rationale", rationale);
        summary.put("agentscope_sessions", rounds);
        summary.put("subagent_mode", "agentscope-java-harness-subagents");
        summary.put("scan_strategy", "candidate-path-whitebox");
        summary.put("analysis_coverage", preparation.analysisSummary());
        summary.put("rounds", rounds);
        summary.put("ceiling_hit", ceilingHit);
        return summary;
    }

    public record AuditResult(
            List<Map<String, Object>> finalFindings,
            Map<String, Object> stats,
            Map<String, Object> taskSummary
    ) { }
}
