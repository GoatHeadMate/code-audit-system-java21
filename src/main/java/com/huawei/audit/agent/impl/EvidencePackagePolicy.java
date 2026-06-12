package com.huawei.audit.agent.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Coverage;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class EvidencePackagePolicy {
    private static final Map<String, Set<String>> HUNTER_SINKS = Map.ofEntries(
            Map.entry("command_injection", Set.of(
                    "COMMAND_EXECUTION",
                    "NATIVE_LIBRARY",
                    "SERVLET_ENTRY"
            )),
            Map.entry("deserialization", Set.of(
                    "NATIVE_DESERIALIZATION",
                    "DYNAMIC_LOADING"
            )),
            Map.entry("ssti", Set.of(
                    "SCRIPT_OR_EXPRESSION_EXECUTION",
                    "DYNAMIC_LOADING"
            )),
            Map.entry("log4j_jndi", Set.of("JNDI_LOOKUP")),
            Map.entry("h2_rce", Set.of(
                    "COMMAND_EXECUTION",
                    "SCRIPT_OR_EXPRESSION_EXECUTION",
                    "DYNAMIC_LOADING"
            )),
            Map.entry("file_upload", Set.of(
                    "COMMAND_EXECUTION",
                    "NATIVE_LIBRARY",
                    "DYNAMIC_LOADING",
                    "FILE_WRITE"
            )),
            Map.entry("ssrf", Set.of(
                    "OUTBOUND_HTTP",
                    "COMMAND_EXECUTION",
                    "JNDI_LOOKUP",
                    "NATIVE_DESERIALIZATION"
            )),
            Map.entry("path_traversal", Set.of("FILE_WRITE")),
            Map.entry("sql_injection", Set.of("SQL_EXECUTION")),
            Map.entry("xss", Set.of("HTTP_RESPONSE_WRITE")),
            Map.entry("xxe", Set.of("XML_PARSE")),
            Map.entry("actuator", Set.of("ACTUATOR_ENDPOINT")),
            Map.entry("crlf_injection", Set.of("HTTP_HEADER_WRITE")),
            Map.entry("open_redirect", Set.of("HTTP_REDIRECT")),
            Map.entry("authorization", Set.of(
                    "COMMAND_EXECUTION",
                    "SCRIPT_OR_EXPRESSION_EXECUTION",
                    "NATIVE_DESERIALIZATION",
                    "DYNAMIC_LOADING",
                    "JNDI_LOOKUP",
                    "NATIVE_LIBRARY",
                    "FILE_WRITE",
                    "OUTBOUND_HTTP",
                    "SERVLET_ENTRY",
                    "FILTER_ENTRY"
            ))
    );

    private EvidencePackagePolicy() {
    }

    static Set<String> sinkCategories(String hunter) {
        return HUNTER_SINKS.getOrDefault(hunter, Set.of());
    }

    static List<CandidatePath> relevantCandidates(
            String hunter,
            List<CandidatePath> candidates
    ) {
        Set<String> categories = HUNTER_SINKS.get(hunter);
        if (categories == null) {
            return List.of();
        }
        return candidates.stream()
                .filter(candidate ->
                        categories.contains(candidate.sink().category()))
                .sorted(candidatePriority())
                .toList();
    }

    static List<StoredCandidate> relevantStoredCandidates(
            String hunter,
            List<StoredCandidate> candidates
    ) {
        Set<String> categories = HUNTER_SINKS.get(hunter);
        if (categories == null) {
            return List.of();
        }
        return candidates.stream()
                .filter(candidate -> categories.contains(
                        candidate.executionPath().sink().category()
                ))
                .sorted(Comparator.comparing(
                        (StoredCandidate c) -> confidenceRank(
                                c.correlationConfidence()
                        )
                ).thenComparingInt(
                        c -> c.executionPath().callDepth()
                ))
                .toList();
    }

    private static Comparator<CandidatePath> candidatePriority() {
        return Comparator
                .comparing((CandidatePath c) -> confidenceRank(
                        c.staticConfidence()
                ))
                .thenComparingInt(CandidatePath::callDepth);
    }

    private static int confidenceRank(String confidence) {
        return switch (confidence) {
            case "HIGH" -> 0;
            case "MEDIUM" -> 1;
            default -> 2;
        };
    }

    static Map<String, Object> coverageSummary(Coverage coverage) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("java_files", coverage.javaFiles());
        summary.put("parsed_methods", coverage.parsedMethods());
        summary.put("discovered_entrypoints", coverage.discoveredEntryPoints());
        summary.put("bound_entrypoints", coverage.boundEntryPoints());
        summary.put("unresolved_entrypoints", coverage.unresolvedEntryPoints());
        summary.put("dangerous_sinks", coverage.dangerousSinks());
        summary.put("candidate_paths", coverage.candidatePaths());
        summary.put("storage_accesses", coverage.storageAccesses());
        summary.put("stored_candidates", coverage.storedCandidates());
        summary.put(
                "entrypoints_reaching_sink",
                coverage.entryPointsReachingSink()
        );
        summary.put("unresolved_calls", coverage.unresolvedCalls());
        summary.put("parser_diagnostics", coverage.parserDiagnostics());
        summary.put("entry_binding_rate", coverage.entryBindingRate());
        summary.put(
                "entrypoints_by_discoverer",
                coverage.entryPointsByDiscoverer()
        );
        summary.put("sinks_by_category", coverage.sinksByCategory());
        summary.put("candidate_paths_by_sink", coverage.candidatePathsBySink());
        return Map.copyOf(summary);
    }
}
