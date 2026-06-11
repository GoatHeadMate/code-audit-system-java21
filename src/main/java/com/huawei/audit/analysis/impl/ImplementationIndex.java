package com.huawei.audit.analysis.impl;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

final class ImplementationIndex {
    private ImplementationIndex() {
    }

    static Map<String, Set<String>> transitive(
            Map<String, Set<String>> direct
    ) {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        for (String parent : direct.keySet()) {
            LinkedHashSet<String> implementations = new LinkedHashSet<>();
            collect(parent, direct, implementations);
            result.put(parent, Set.copyOf(implementations));
        }
        return Map.copyOf(result);
    }

    private static void collect(
            String parent,
            Map<String, Set<String>> direct,
            Set<String> collected
    ) {
        String simpleParent = AnalysisTextUtils.simpleName(parent);
        for (String implementation : direct.getOrDefault(
                simpleParent,
                Set.of()
        )) {
            String simpleImplementation = AnalysisTextUtils.simpleName(
                    implementation
            );
            if (collected.add(simpleImplementation)) {
                collect(simpleImplementation, direct, collected);
            }
        }
    }
}
