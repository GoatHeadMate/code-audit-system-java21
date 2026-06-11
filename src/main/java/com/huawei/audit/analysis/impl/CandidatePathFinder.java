package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class CandidatePathFinder {
    private static final int MAX_PATH_DEPTH = 12;
    private static final int MAX_CANDIDATES = 1_000;

    List<CandidatePath> find(
            List<EntryPoint> entryPoints,
            SourceIndex index,
            CallGraph graph
    ) {
        Map<String, List<Sink>> sinksByMethod = index.sinks().stream()
                .collect(Collectors.groupingBy(
                        Sink::methodId,
                        LinkedHashMap::new,
                        Collectors.toList()
                ));
        List<CandidatePath> candidates = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Map<String, Integer> sinkDistances = ReverseReachability.distances(
                graph,
                sinksByMethod.keySet(),
                MAX_PATH_DEPTH
        );
        int sequence = 1;

        for (EntryPoint entryPoint : entryPoints) {
            if (entryPoint.methodId().isBlank()
                    || !sinkDistances.containsKey(entryPoint.methodId())) {
                continue;
            }
            Deque<PathState> queue = new ArrayDeque<>();
            queue.add(new PathState(
                    entryPoint.methodId(),
                    List.of(entryPoint.methodId()),
                    List.of(),
                    Set.of(entryPoint.methodId())
            ));
            while (!queue.isEmpty() && candidates.size() < MAX_CANDIDATES) {
                PathState state = queue.removeFirst();
                for (Sink sink : sinksByMethod.getOrDefault(
                        state.methodId(),
                        List.of()
                )) {
                    String key = entryPoint.id() + "|" + sink.id() + "|"
                            + String.join(">", state.methodPath());
                    if (seen.add(key)) {
                        candidates.add(new CandidatePath(
                                "candidate-" + sequence++,
                                entryPoint,
                                sink,
                                toSteps(state.methodPath(), index),
                                state.edges(),
                                confidence(state.edges()),
                                state.edges().size(),
                                "PENDING_CLAUDE_REVIEW"
                        ));
                    }
                }
                expand(queue, state, graph, sinkDistances);
            }
        }
        return List.copyOf(candidates);
    }

    private void expand(
            Deque<PathState> queue,
            PathState state,
            CallGraph graph,
            Map<String, Integer> sinkDistances
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
            Integer distance = sinkDistances.get(edge.toMethodId());
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
        List<MethodStep> steps = new ArrayList<>();
        for (String methodId : methodPath) {
            MethodNode method = index.methodsById().get(methodId);
            if (method != null) {
                steps.add(new MethodStep(
                        method.id(),
                        method.className(),
                        method.methodName(),
                        method.filePath(),
                        method.startLine(),
                        method.endLine(),
                        method.signature()
                ));
            }
        }
        return List.copyOf(steps);
    }

    private String confidence(List<CallEdge> edges) {
        if (edges.stream().allMatch(edge -> Set.of(
                "receiver-type",
                "same-class",
                "interface-implementation",
                "static-class-name"
        ).contains(edge.resolution()))) {
            return "HIGH";
        }
        return edges.stream().anyMatch(edge ->
                "unique-method-name".equals(edge.resolution()))
                ? "MEDIUM"
                : "LOW";
    }

    private record PathState(
            String methodId,
            List<String> methodPath,
            List<CallEdge> edges,
            Set<String> visited
    ) { }
}
