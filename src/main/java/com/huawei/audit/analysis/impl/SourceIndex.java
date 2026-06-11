package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageAccess;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

record SourceIndex(
        List<MethodNode> methods,
        List<Sink> sinks,
        List<StorageAccess> storageAccesses,
        Map<String, MethodNode> methodsById,
        Map<String, List<MethodNode>> methodsByName,
        Map<String, List<MethodNode>> methodsByClassAndName,
        Map<String, Set<String>> implementations,
        List<String> parseErrors
) {
    static SourceIndex empty() {
        return new SourceIndex(
                List.of(),
                List.of(),
                List.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                List.of()
        );
    }

    static SourceIndex create(
            List<MethodNode> methods,
            List<Sink> sinks,
            Map<String, Set<String>> implementations,
            List<String> parseErrors
    ) {
        Map<String, MethodNode> byId = methods.stream().collect(Collectors.toMap(
                MethodNode::id,
                method -> method,
                (left, right) -> left,
                LinkedHashMap::new
        ));
        Map<String, List<MethodNode>> byName = methods.stream().collect(
                Collectors.groupingBy(
                        MethodNode::methodName,
                        LinkedHashMap::new,
                        Collectors.toList()
                )
        );
        Map<String, List<MethodNode>> byClassAndName = methods.stream().collect(
                Collectors.groupingBy(
                        method -> method.className() + "#" + method.methodName(),
                        LinkedHashMap::new,
                        Collectors.toList()
                )
        );
        Map<String, Sink> deduplicatedSinks = new LinkedHashMap<>();
        for (Sink sink : sinks) {
            deduplicatedSinks.putIfAbsent(
                    sink.methodId() + "|" + sink.category() + "|"
                            + sink.filePath() + "|" + sink.line(),
                    sink
            );
        }
        return new SourceIndex(
                List.copyOf(methods),
                List.copyOf(deduplicatedSinks.values()),
                methods.stream()
                        .flatMap(method -> method.storageAccesses().stream())
                        .toList(),
                Map.copyOf(byId),
                Map.copyOf(byName),
                Map.copyOf(byClassAndName),
                implementations.entrySet().stream().collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> Set.copyOf(entry.getValue()),
                        (left, right) -> left,
                        LinkedHashMap::new
                )),
                List.copyOf(parseErrors)
        );
    }
}
