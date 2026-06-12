package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Coverage;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

final class CoverageCalculator {
    Coverage calculate(
            Path sourceRoot,
            SourceIndex sourceIndex,
            CallGraph callGraph,
            List<EntryPoint> entryPoints,
            List<CandidatePath> candidates,
            List<StoredCandidate> storedCandidates,
            long llmExpandedRules,
            long llmReviewedSinks
    ) throws IOException {
        long javaFiles;
        try (var files = Files.walk(sourceRoot)) {
            javaFiles = files
                    .filter(Files::isRegularFile)
                    .filter(path ->
                            path.getFileName().toString().endsWith(".java"))
                    .count();
        }
        long boundEntries = entryPoints.stream()
                .filter(entry -> "BOUND".equals(entry.bindingStatus()))
                .count();
        long entriesWithCandidates = candidates.stream()
                .map(candidate -> candidate.entryPoint().id())
                .distinct()
                .count();
        return new Coverage(
                javaFiles,
                sourceIndex.methods().size(),
                entryPoints.size(),
                boundEntries,
                entryPoints.size() - boundEntries,
                sourceIndex.sinks().size(),
                candidates.size(),
                sourceIndex.storageAccesses().size(),
                storedCandidates.size(),
                entriesWithCandidates,
                callGraph.unresolvedCalls().size(),
                sourceIndex.parseErrors().size(),
                ratio(boundEntries, entryPoints.size()),
                entryPoints.stream().collect(Collectors.groupingBy(
                        EntryPoint::discoverySource,
                        LinkedHashMap::new,
                        Collectors.counting()
                )),
                sourceIndex.sinks().stream().collect(Collectors.groupingBy(
                        Sink::category,
                        LinkedHashMap::new,
                        Collectors.counting()
                )),
                candidates.stream().collect(Collectors.groupingBy(
                        candidate -> candidate.sink().category(),
                        LinkedHashMap::new,
                        Collectors.counting()
                )),
                llmExpandedRules,
                llmReviewedSinks
        );
    }

    private double ratio(long numerator, long denominator) {
        if (denominator == 0) {
            return 1.0;
        }
        return Math.round((double) numerator / denominator * 10_000.0)
                / 10_000.0;
    }
}
