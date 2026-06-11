package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ReverseReachability {
    private ReverseReachability() {
    }

    static Map<String, Integer> distances(
            CallGraph graph,
            Set<String> targets,
            int maxDepth
    ) {
        Map<String, List<String>> incoming = new LinkedHashMap<>();
        graph.outgoing().values().forEach(edges -> {
            for (CallEdge edge : edges) {
                incoming.computeIfAbsent(
                        edge.toMethodId(),
                        ignored -> new ArrayList<>()
                ).add(edge.fromMethodId());
            }
        });

        Map<String, Integer> distances = new LinkedHashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        for (String target : targets) {
            distances.put(target, 0);
            queue.addLast(target);
        }
        while (!queue.isEmpty()) {
            String methodId = queue.removeFirst();
            int distance = distances.get(methodId);
            if (distance >= maxDepth) {
                continue;
            }
            for (String caller : incoming.getOrDefault(methodId, List.of())) {
                if (distances.putIfAbsent(caller, distance + 1) == null) {
                    queue.addLast(caller);
                }
            }
        }
        return Map.copyOf(distances);
    }
}
