package com.huawei.audit.agent.impl;

import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.huawei.audit.agent.ClaudeGateway;
import com.huawei.audit.agent.EvidencePreparationService;
import com.huawei.audit.analysis.WhiteBoxAnalysisService;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import com.huawei.audit.config.AuditProperties;
import com.huawei.audit.config.OrchestratorProperties;
import com.huawei.audit.domain.AuditJob;
import com.huawei.audit.job.JobLogBroker;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Service;

@Service
public class EvidencePreparationServiceImpl implements EvidencePreparationService {
    private static final int ITEMS_PER_CHUNK = 50;
    private static final int MAX_CHUNK_BYTES = 64 * 1_024;
    private static final int MAX_UNRESOLVED_CALLS_WRITTEN = 5_000;
    private static final List<String> REVIEW_CONTRACT = List.of(
            "Review every candidate path in this package.",
            "Review every stored candidate as a two-stage flow: HTTP write path, storage boundary, then execution path.",
            "For stored candidates, confirm entity/field/key correspondence between WRITE and READ; repository identity alone is supporting evidence, not proof.",
            "Check whether unvalidated fields are concatenated or bound before expression, script, reflection, deserialization or command execution.",
            "Confirm scheduled/message/event execution is automatic or attacker-triggerable.",
            "Confirm request-value controllability across the path.",
            "Inspect authentication, authorization and global filters.",
            "Validate sanitizers, quoting and allowlists in source.",
            "Reject paths broken by impossible dispatch or trusted data.",
            "Use Glob/Grep/Read only to resolve missing evidence.",
            "Do not perform an unbounded repository-wide audit."
    );

    private final WhiteBoxAnalysisService analysisService;
    private final ObjectMapper objectMapper;
    private final ObjectWriter prettyWriter;
    private final JobLogBroker logs;
    private final ClaudeGateway claudeGateway;
    private final OrchestratorProperties orchestratorProperties;
    private final Semaphore analysisSlot = new Semaphore(1, true);
    private final long analysisTimeoutMs;

    public EvidencePreparationServiceImpl(
            WhiteBoxAnalysisService analysisService,
            ObjectMapper objectMapper,
            JobLogBroker logs,
            AuditProperties properties,
            OrchestratorProperties orchestratorProperties,
            ClaudeGateway claudeGateway
    ) {
        this.analysisService = analysisService;
        this.objectMapper = objectMapper;
        var printer = new DefaultPrettyPrinter()
                .withArrayIndenter(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
        this.prettyWriter = objectMapper.writer(printer);
        this.logs = logs;
        this.analysisTimeoutMs = properties.hunterTimeout().toMillis();
        this.orchestratorProperties = orchestratorProperties;
        this.claudeGateway = claudeGateway;
    }

    @Override
    public PreparationResult prepare(
            AuditJob job, Path sourceRoot,
            List<String> hunters, List<Map<String, String>> dependencies
    ) throws Exception {
        Path evidenceDirectory = job.workDir().resolve("evidence");
        Path analysisDirectory = evidenceDirectory.resolve("whitebox");
        Path packageDirectory = evidenceDirectory.resolve("packages");
        Files.createDirectories(analysisDirectory);
        Files.createDirectories(packageDirectory);

        var analysis = runWhiteBoxAnalysis(job, sourceRoot, dependencies);
        writeJson(analysisDirectory.resolve("entrypoints.json"), analysis.entryPoints());
        writeJson(analysisDirectory.resolve("sinks.json"), analysis.sinks());
        writeJson(analysisDirectory.resolve("storage-accesses.json"), analysis.storageAccesses());
        writeJson(analysisDirectory.resolve("unresolved-calls.json"), Map.of(
                "total", analysis.unresolvedCalls().size(),
                "stored", Math.min(MAX_UNRESOLVED_CALLS_WRITTEN, analysis.unresolvedCalls().size()),
                "truncated", analysis.unresolvedCalls().size() > MAX_UNRESOLVED_CALLS_WRITTEN,
                "items", analysis.unresolvedCalls().stream().limit(MAX_UNRESOLVED_CALLS_WRITTEN).toList()
        ));
        writeJson(analysisDirectory.resolve("parser-diagnostics.json"), analysis.parserDiagnostics());
        writeJson(analysisDirectory.resolve("coverage.json"), analysis.coverage());
        List<String> allCandidateChunks = writeChunks(
                analysisDirectory, "candidate-paths", analysis.candidatePaths());
        List<String> allStoredCandidateChunks = writeChunks(
                analysisDirectory, "stored-candidates", analysis.storedCandidates());

        Path indexFile = analysisDirectory.resolve("index.json");
        Map<String, Object> index = new LinkedHashMap<>();
        index.put("mode", "candidate-path-whitebox");
        index.put("source_root", sourceRoot.toAbsolutePath().normalize().toString());
        index.put("entrypoints", absolute(analysisDirectory.resolve("entrypoints.json")));
        index.put("sinks", absolute(analysisDirectory.resolve("sinks.json")));
        index.put("storage_accesses", absolute(analysisDirectory.resolve("storage-accesses.json")));
        index.put("candidate_path_chunks", allCandidateChunks);
        index.put("stored_candidate_chunks", allStoredCandidateChunks);
        index.put("unresolved_calls", absolute(analysisDirectory.resolve("unresolved-calls.json")));
        index.put("coverage", absolute(analysisDirectory.resolve("coverage.json")));
        index.put("parser_diagnostics", absolute(analysisDirectory.resolve("parser-diagnostics.json")));
        var cov = analysis.coverage();
        index.put("summary", Map.of(
                "java_files", cov.javaFiles(),
                "parsed_methods", cov.parsedMethods(),
                "entrypoints", cov.discoveredEntryPoints(),
                "sinks", cov.dangerousSinks(),
                "candidate_paths", cov.candidatePaths(),
                "stored_candidates", cov.storedCandidates()
        ));
        writeJson(indexFile, index);

        Map<String, String> manifest = new LinkedHashMap<>();
        List<String> expandedCandidates = new ArrayList<>();
        int maxChunks = orchestratorProperties.maxChunksPerBatch();

        for (String hunter : hunters) {
            List<CandidatePath> relevant = EvidencePackagePolicy.relevantCandidates(
                    hunter, analysis.candidatePaths());
            List<StoredCandidate> relevantStored = EvidencePackagePolicy.relevantStoredCandidates(
                    hunter, analysis.storedCandidates());
            Path hunterDir = packageDirectory.resolve(hunter);
            Files.createDirectories(hunterDir);
            List<String> candChunks = writeChunks(hunterDir, "candidates", relevant);
            List<String> storedChunks = writeChunks(hunterDir, "stored-candidates", relevantStored);

            int totalChunks = candChunks.size() + storedChunks.size();
            if (totalChunks <= maxChunks) {
                Path taskFile = hunterDir.resolve("task.json");
                writeTaskFile(taskFile, hunter, sourceRoot, indexFile,
                        relevant.size(), candChunks, relevantStored.size(), storedChunks, analysis);
                manifest.put(hunter, absolute(taskFile));
                expandedCandidates.add(hunter);
            } else {
                splitIntoBatches(hunter, hunterDir, sourceRoot, indexFile, relevant.size(),
                        candChunks, relevantStored.size(), storedChunks, analysis,
                        maxChunks, manifest, expandedCandidates, job);
            }
        }

        Files.writeString(evidenceDirectory.resolve("manifest.json"),
                prettyWriter.writeValueAsString(manifest));
        var coverage = analysis.coverage();
        logs.publish(job,
                "[whitebox] entrypoints=" + coverage.discoveredEntryPoints()
                        + ", bound=" + coverage.boundEntryPoints()
                        + ", methods=" + coverage.parsedMethods()
                        + ", sinks=" + coverage.dangerousSinks()
                        + ", candidate_paths=" + coverage.candidatePaths()
                        + ", storage_accesses=" + coverage.storageAccesses()
                        + ", stored_candidates=" + coverage.storedCandidates()
                        + ", unresolved_calls=" + coverage.unresolvedCalls()
                        + ", total_subagents=" + expandedCandidates.size());
        return new PreparationResult(
                Map.copyOf(manifest),
                EvidencePackagePolicy.coverageSummary(coverage),
                List.copyOf(expandedCandidates));
    }

    private void splitIntoBatches(
            String hunter, Path hunterDir, Path sourceRoot, Path indexFile,
            int totalCandidates, List<String> candChunks,
            int totalStored, List<String> storedChunks,
            WhiteBoxAnalysisService.AnalysisResult analysis,
            int maxChunks, Map<String, String> manifest,
            List<String> expandedCandidates, AuditJob job
    ) throws Exception {
        int totalChunks = candChunks.size() + storedChunks.size();
        int batchCount = (totalChunks + maxChunks - 1) / maxChunks;
        int candPerBatch = (candChunks.size() + batchCount - 1) / batchCount;
        int storedPerBatch = (storedChunks.size() + batchCount - 1) / batchCount;
        logs.publish(job, "[whitebox] splitting " + hunter + " into " + batchCount
                + " batches (total_chunks=" + totalChunks + ", max=" + maxChunks + ")");
        for (int b = 0; b < batchCount; b++) {
            String batchName = hunter + "_batch_" + (b + 1);
            List<String> bc = sliceChunks(candChunks, b, candPerBatch);
            List<String> bs = sliceChunks(storedChunks, b, storedPerBatch);
            int bcCount = candChunks.isEmpty() ? 0
                    : (int) Math.ceil((double) totalCandidates * bc.size() / candChunks.size());
            int bsCount = storedChunks.isEmpty() ? 0
                    : (int) Math.ceil((double) totalStored * bs.size() / storedChunks.size());
            Path batchFile = hunterDir.resolve("task-batch-" + (b + 1) + ".json");
            writeTaskFile(batchFile, hunter, sourceRoot, indexFile, bcCount, bc, bsCount, bs, analysis);
            manifest.put(batchName, absolute(batchFile));
            expandedCandidates.add(batchName);
        }
    }

    private List<String> sliceChunks(List<String> chunks, int batch, int perBatch) {
        if (perBatch == 0 || chunks.isEmpty()) return List.of();
        int start = batch * perBatch;
        if (start >= chunks.size()) return List.of();
        return chunks.subList(start, Math.min(start + perBatch, chunks.size()));
    }

    private void writeTaskFile(
            Path taskFile, String hunter, Path sourceRoot, Path indexFile,
            int candidateCount, List<String> candidateChunks,
            int storedCount, List<String> storedChunks,
            WhiteBoxAnalysisService.AnalysisResult analysis
    ) throws Exception {
        Map<String, Object> task = new LinkedHashMap<>();
        task.put("mode", "candidate-path-whitebox");
        task.put("hunter", hunter);
        task.put("source_root", sourceRoot.toAbsolutePath().normalize().toString());
        task.put("analysis_index", absolute(indexFile));
        task.put("candidate_sink_categories", EvidencePackagePolicy.sinkCategories(hunter));
        task.put("candidate_count", candidateCount);
        task.put("candidate_chunks", candidateChunks);
        task.put("stored_candidate_count", storedCount);
        task.put("stored_candidate_chunks", storedChunks);
        task.put("unresolved_entrypoints", analysis.entryPoints().stream()
                .filter(entry -> "UNRESOLVED".equals(entry.bindingStatus())).toList());
        task.put("review_contract", REVIEW_CONTRACT);
        writeJson(taskFile, task);
    }

    private WhiteBoxAnalysisService.AnalysisResult runWhiteBoxAnalysis(
            AuditJob job, Path sourceRoot, List<Map<String, String>> dependencies
    ) throws Exception {
        if (!analysisSlot.tryAcquire()) {
            logs.publish(job, "[whitebox] waiting for the active analysis to release memory");
            if (!analysisSlot.tryAcquire(analysisTimeoutMs, TimeUnit.MILLISECONDS)) {
                throw new IOException("timed out waiting for white-box analysis slot");
            }
        }
        try {
            logs.publish(job, "[whitebox] indexing source in bounded batches");
            return analysisService.analyze(
                    sourceRoot,
                    dependencies,
                    claudeGateway
            );
        } finally {
            analysisSlot.release();
        }
    }

    private List<String> writeChunks(Path directory, String prefix, List<?> items) throws Exception {
        List<String> chunks = new ArrayList<>();
        int start = 0;
        int chunkNumber = 1;
        while (start < items.size()) {
            int end = start;
            Map<String, Object> content = null;
            while (end < items.size() && end - start < ITEMS_PER_CHUNK) {
                var candidate = Map.of(
                        "start_index", start, "end_index", end, "items", items.subList(start, end + 1));
                int size = prettyWriter.writeValueAsBytes(candidate).length;
                if (size > MAX_CHUNK_BYTES && end > start) break;
                content = candidate;
                end++;
                if (size > MAX_CHUNK_BYTES) break;
            }
            Path chunk = directory.resolve("%s-%04d.json".formatted(prefix, chunkNumber));
            writeJson(chunk, content);
            chunks.add(absolute(chunk));
            start = end;
            chunkNumber++;
        }
        if (chunks.isEmpty()) {
            Path chunk = directory.resolve(prefix + "-0001.json");
            writeJson(chunk, Map.of("start_index", 0, "end_index", -1, "items", List.of()));
            chunks.add(absolute(chunk));
        }
        return List.copyOf(chunks);
    }

    private void writeJson(Path path, Object value) throws Exception {
        prettyWriter.writeValue(path.toFile(), value);
    }

    private String absolute(Path path) {
        return path.toAbsolutePath().normalize().toString();
    }
}
