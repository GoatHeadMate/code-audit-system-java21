package com.huawei.audit.agent.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.agent.EvidencePreparationService;
import com.huawei.audit.analysis.WhiteBoxAnalysisService;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import com.huawei.audit.config.AuditProperties;
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
    private static final int MAX_UNRESOLVED_CALLS_WRITTEN = 5_000;

    private final WhiteBoxAnalysisService analysisService;
    private final ObjectMapper objectMapper;
    private final JobLogBroker logs;
    private final Semaphore analysisSlot = new Semaphore(1, true);
    private final long analysisTimeoutMs;

    public EvidencePreparationServiceImpl(
            WhiteBoxAnalysisService analysisService,
            ObjectMapper objectMapper,
            JobLogBroker logs,
            AuditProperties properties
    ) {
        this.analysisService = analysisService;
        this.objectMapper = objectMapper;
        this.logs = logs;
        this.analysisTimeoutMs = properties.hunterTimeout().toMillis();
    }

    @Override
    public PreparationResult prepare(
            AuditJob job,
            Path sourceRoot,
            List<String> hunters
    ) throws Exception {
        Path evidenceDirectory = job.workDir().resolve("evidence");
        Path analysisDirectory = evidenceDirectory.resolve("whitebox");
        Path packageDirectory = evidenceDirectory.resolve("packages");
        Files.createDirectories(analysisDirectory);
        Files.createDirectories(packageDirectory);

        var analysis = runWhiteBoxAnalysis(job, sourceRoot);
        writeJson(
                analysisDirectory.resolve("entrypoints.json"),
                analysis.entryPoints()
        );
        writeJson(
                analysisDirectory.resolve("sinks.json"),
                analysis.sinks()
        );
        writeJson(
                analysisDirectory.resolve("storage-accesses.json"),
                analysis.storageAccesses()
        );
        writeJson(
                analysisDirectory.resolve("unresolved-calls.json"),
                Map.of(
                        "total", analysis.unresolvedCalls().size(),
                        "stored", Math.min(
                                MAX_UNRESOLVED_CALLS_WRITTEN,
                                analysis.unresolvedCalls().size()
                        ),
                        "truncated", analysis.unresolvedCalls().size()
                                > MAX_UNRESOLVED_CALLS_WRITTEN,
                        "items", analysis.unresolvedCalls().stream()
                                .limit(MAX_UNRESOLVED_CALLS_WRITTEN)
                                .toList()
                )
        );
        writeJson(
                analysisDirectory.resolve("parser-diagnostics.json"),
                analysis.parserDiagnostics()
        );
        writeJson(
                analysisDirectory.resolve("coverage.json"),
                analysis.coverage()
        );
        List<String> allCandidateChunks = writeChunks(
                analysisDirectory,
                "candidate-paths",
                analysis.candidatePaths()
        );
        List<String> allStoredCandidateChunks = writeChunks(
                analysisDirectory,
                "stored-candidates",
                analysis.storedCandidates()
        );

        Path indexFile = analysisDirectory.resolve("index.json");
        Map<String, Object> index = new LinkedHashMap<>();
        index.put("mode", "candidate-path-whitebox");
        index.put(
                "source_root",
                sourceRoot.toAbsolutePath().normalize().toString()
        );
        index.put(
                "entrypoints",
                absolute(analysisDirectory.resolve("entrypoints.json"))
        );
        index.put("sinks", absolute(analysisDirectory.resolve("sinks.json")));
        index.put(
                "storage_accesses",
                absolute(analysisDirectory.resolve("storage-accesses.json"))
        );
        index.put("candidate_path_chunks", allCandidateChunks);
        index.put("stored_candidate_chunks", allStoredCandidateChunks);
        index.put(
                "unresolved_calls",
                absolute(analysisDirectory.resolve("unresolved-calls.json"))
        );
        index.put(
                "coverage",
                absolute(analysisDirectory.resolve("coverage.json"))
        );
        index.put(
                "parser_diagnostics",
                absolute(analysisDirectory.resolve("parser-diagnostics.json"))
        );
        index.put("summary", analysis.coverage());
        index.put("codeql_used", false);
        writeJson(indexFile, index);

        Map<String, String> manifest = new LinkedHashMap<>();
        for (String hunter : hunters) {
            List<CandidatePath> relevant = EvidencePackagePolicy.relevantCandidates(
                    hunter,
                    analysis.candidatePaths()
            );
            List<StoredCandidate> relevantStored =
                    EvidencePackagePolicy.relevantStoredCandidates(
                            hunter,
                            analysis.storedCandidates()
                    );
            Path hunterDirectory = packageDirectory.resolve(hunter);
            Files.createDirectories(hunterDirectory);
            List<String> candidateChunks = writeChunks(
                    hunterDirectory,
                    "candidates",
                    relevant
            );
            List<String> storedCandidateChunks = writeChunks(
                    hunterDirectory,
                    "stored-candidates",
                    relevantStored
            );
            Path hunterFile = hunterDirectory.resolve("task.json");
            Map<String, Object> task = new LinkedHashMap<>();
            task.put("mode", "candidate-path-whitebox");
            task.put("hunter", hunter);
            task.put(
                    "source_root",
                    sourceRoot.toAbsolutePath().normalize().toString()
            );
            task.put("analysis_index", absolute(indexFile));
            task.put(
                    "candidate_sink_categories",
                    EvidencePackagePolicy.sinkCategories(hunter)
            );
            task.put("candidate_count", relevant.size());
            task.put("candidate_chunks", candidateChunks);
            task.put("stored_candidate_count", relevantStored.size());
            task.put("stored_candidate_chunks", storedCandidateChunks);
            task.put(
                    "unresolved_entrypoints",
                    analysis.entryPoints().stream()
                            .filter(entry -> "UNRESOLVED".equals(
                                    entry.bindingStatus()
                            ))
                            .toList()
            );
            task.put(
                    "review_contract",
                    List.of(
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
                    )
            );
            writeJson(hunterFile, task);
            manifest.put(hunter, absolute(hunterFile));
        }

        Files.writeString(
                evidenceDirectory.resolve("manifest.json"),
                objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(manifest)
        );
        var coverage = analysis.coverage();
        logs.publish(
                job,
                "[whitebox] entrypoints=" + coverage.discoveredEntryPoints()
                        + ", bound=" + coverage.boundEntryPoints()
                        + ", methods=" + coverage.parsedMethods()
                        + ", sinks=" + coverage.dangerousSinks()
                        + ", candidate_paths=" + coverage.candidatePaths()
                        + ", storage_accesses=" + coverage.storageAccesses()
                        + ", stored_candidates=" + coverage.storedCandidates()
                        + ", unresolved_calls=" + coverage.unresolvedCalls()
        );
        return new PreparationResult(
                Map.copyOf(manifest),
                EvidencePackagePolicy.coverageSummary(coverage)
        );
    }

    private WhiteBoxAnalysisService.AnalysisResult runWhiteBoxAnalysis(
            AuditJob job,
            Path sourceRoot
    ) throws Exception {
        if (!analysisSlot.tryAcquire()) {
            logs.publish(job, "[whitebox] waiting for the active analysis to release memory");
            if (!analysisSlot.tryAcquire(analysisTimeoutMs, TimeUnit.MILLISECONDS)) {
                throw new IOException("timed out waiting for white-box analysis slot");
            }
        }
        try {
            logs.publish(
                    job,
                    "[whitebox] indexing source in bounded batches"
            );
            return analysisService.analyze(sourceRoot);
        } finally {
            analysisSlot.release();
        }
    }

    private List<String> writeChunks(
            Path directory,
            String prefix,
            List<?> items
    ) throws Exception {
        List<String> chunks = new ArrayList<>();
        for (int start = 0; start < items.size(); start += ITEMS_PER_CHUNK) {
            int end = Math.min(start + ITEMS_PER_CHUNK, items.size());
            Path chunk = directory.resolve(
                    "%s-%04d.json".formatted(
                            prefix,
                            start / ITEMS_PER_CHUNK + 1
                    )
            );
            Map<String, Object> content = new LinkedHashMap<>();
            content.put("start_index", start);
            content.put("end_index", end - 1);
            content.put("items", items.subList(start, end));
            writeJson(chunk, content);
            chunks.add(absolute(chunk));
        }
        if (chunks.isEmpty()) {
            Path chunk = directory.resolve(prefix + "-0001.json");
            writeJson(
                    chunk,
                    Map.of(
                            "start_index", 0,
                            "end_index", -1,
                            "items", List.of()
                    )
            );
            chunks.add(absolute(chunk));
        }
        return List.copyOf(chunks);
    }

    private void writeJson(Path path, Object value) throws Exception {
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(
                path.toFile(),
                value
        );
    }

    private String absolute(Path path) {
        return path.toAbsolutePath().normalize().toString();
    }

}
