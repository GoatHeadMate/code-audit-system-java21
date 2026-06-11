package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageAccess;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageWritePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class StoredCandidateCorrelator {
    private static final int MAX_STORED_CANDIDATES = 500;

    List<StoredCandidate> correlate(
            List<StorageWritePath> writePaths,
            List<CandidatePath> executionPaths,
            SourceIndex index
    ) {
        List<StoredCandidate> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int sequence = 1;

        for (CandidatePath execution : executionPaths) {
            for (StorageAccess read : readsOn(execution, index)) {
                for (StorageWritePath write : writePaths) {
                    if (!sameStorage(write.writeAccess(), read)) {
                        continue;
                    }
                    String key = write.entryPoint().id() + "|"
                            + read.id() + "|" + execution.sink().id();
                    if (!seen.add(key)) {
                        continue;
                    }
                    result.add(new StoredCandidate(
                            "stored-candidate-" + sequence++,
                            read.storageKey(),
                            write,
                            execution,
                            read,
                            correlationConfidence(write.writeAccess(), read),
                            "PENDING_CLAUDE_REVIEW"
                    ));
                    if (result.size() >= MAX_STORED_CANDIDATES) {
                        return List.copyOf(result);
                    }
                }
            }
        }
        return List.copyOf(result);
    }

    private List<StorageAccess> readsOn(
            CandidatePath execution,
            SourceIndex index
    ) {
        List<StorageAccess> reads = new ArrayList<>();
        for (MethodStep step : execution.methodPath()) {
            var method = index.methodsById().get(step.methodId());
            if (method == null) {
                continue;
            }
            method.storageAccesses().stream()
                    .filter(access -> "READ".equals(access.kind()))
                    .forEach(reads::add);
        }
        return reads;
    }

    private boolean sameStorage(StorageAccess write, StorageAccess read) {
        return write.storageKey().equalsIgnoreCase(read.storageKey());
    }

    private String correlationConfidence(
            StorageAccess write,
            StorageAccess read
    ) {
        if (!write.valueType().isBlank()
                && write.valueType().equalsIgnoreCase(read.valueType())) {
            return "HIGH";
        }
        return "MEDIUM";
    }
}
