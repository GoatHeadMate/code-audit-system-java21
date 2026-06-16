package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageAccess;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageWritePath;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class StorageWritePathFinder {
    private static final int MAX_PATH_DEPTH = 12;
    private static final int MAX_PATHS = 1_000;

    List<StorageWritePath> find(
            List<EntryPoint> entryPoints,
            SourceIndex index,
            CallGraph graph
    ) {
        List<StorageWritePath> paths = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Set<String> writeMethods = index.storageAccesses().stream()
                .filter(access -> "WRITE".equals(access.kind()))
                .map(StorageAccess::methodId)
                .collect(Collectors.toSet());
        Map<String, Integer> writeDistances = ReverseReachability.distances(
                graph,
                writeMethods,
                MAX_PATH_DEPTH
        );
        for (EntryPoint entryPoint : entryPoints) {
            if (!isExternalWriteEntry(entryPoint)
                    || entryPoint.methodId().isBlank()
                    || !writeDistances.containsKey(entryPoint.methodId())) {
                continue;
            }
            walk(
                    entryPoint,
                    index,
                    graph,
                    writeDistances,
                    paths,
                    seen
            );
            if (paths.size() >= MAX_PATHS) {
                break;
            }
        }
        return List.copyOf(paths);
    }

    private boolean isExternalWriteEntry(EntryPoint entryPoint) {
        return "HTTP".equalsIgnoreCase(entryPoint.protocol())
                || "message".equalsIgnoreCase(entryPoint.protocol());
    }

    private void walk(
            EntryPoint entryPoint,
            SourceIndex index,
            CallGraph graph,
            Map<String, Integer> writeDistances,
            List<StorageWritePath> paths,
            Set<String> seen
    ) {
        Deque<PathState> queue = new ArrayDeque<>();
        queue.add(new PathState(
                entryPoint.methodId(),
                List.of(entryPoint.methodId()),
                List.of(),
                Set.of(entryPoint.methodId())
        ));
        while (!queue.isEmpty() && paths.size() < MAX_PATHS) {
            PathState state = queue.removeFirst();
            MethodNode method = index.methodsById().get(state.methodId());
            if (method == null) {
                continue;
            }
            for (StorageAccess access : method.storageAccesses()) {
                String key = entryPoint.id() + "|" + access.id();
                if ("WRITE".equals(access.kind()) && seen.add(key)) {
                    paths.add(new StorageWritePath(
                            entryPoint,
                            access,
                            toSteps(state.methodPath(), index),
                            state.edges(),
                            confidence(state.edges())
                    ));
                }
            }
            expand(queue, state, graph, writeDistances);
        }
    }

    private void expand(
            Deque<PathState> queue,
            PathState state,
            CallGraph graph,
            Map<String, Integer> writeDistances
    ) {
        if (state.edges().size() >= MAX_PATH_DEPTH) {
            return;
        }
        for (CallEdge edge : graph.outgoing()
                .getOrDefault(state.methodId(), List.of())) {
            if (state.visited().contains(edge.toMethodId())) {
                continue;
            }
            int nextDepth = state.edges().size() + 1;
            int remaining = MAX_PATH_DEPTH - nextDepth;
            Integer distance = writeDistances.get(edge.toMethodId());
            if (distance == null || distance > remaining) {
                continue;
            }
            List<String> methodPath = new ArrayList<>(state.methodPath());
            methodPath.add(edge.toMethodId());
            List<CallEdge> edges = new ArrayList<>(state.edges());
            edges.add(edge);
            Set<String> visited = new LinkedHashSet<>(state.visited());
            visited.add(edge.toMethodId());
            queue.addLast(new PathState(
                    edge.toMethodId(),
                    List.copyOf(methodPath),
                    List.copyOf(edges),
                    Set.copyOf(visited)
            ));
        }
    }

    private List<MethodStep> toSteps(
            List<String> methodPath,
            SourceIndex index
    ) {
        return methodPath.stream()
                .map(index.methodsById()::get)
                .filter(java.util.Objects::nonNull)
                .map(method -> new MethodStep(
                        method.id(),
                        method.className(),
                        method.methodName(),
                        method.parameterCount(),
                        method.filePath(),
                        method.startLine(),
                        method.endLine(),
                        method.signature()
                ))
                .toList();
    }

    private String confidence(List<CallEdge> edges) {
        return edges.stream().anyMatch(edge ->
                edge.resolution().startsWith("unique-method-name"))
                ? "MEDIUM"
                : "HIGH";
    }

    private record PathState(
            String methodId,
            List<String> methodPath,
            List<CallEdge> edges,
            Set<String> visited
    ) { }
}
