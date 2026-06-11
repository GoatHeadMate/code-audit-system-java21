package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.UnresolvedCall;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class CallGraphBuilder {
    private static final int MAX_TARGETS_PER_CALL = 12;

    CallGraph build(SourceIndex index) {
        Map<String, List<CallEdge>> outgoing = new LinkedHashMap<>();
        List<UnresolvedCall> unresolved = new ArrayList<>();

        for (MethodNode method : index.methods()) {
            List<CallEdge> edges = new ArrayList<>();
            for (CallSite call : method.calls()) {
                List<ResolvedTarget> targets = resolveTargets(method, call, index);
                if (targets.isEmpty()) {
                    unresolved.add(new UnresolvedCall(
                            method.id(),
                            method.filePath(),
                            call.line(),
                            call.expression()
                    ));
                    continue;
                }
                for (ResolvedTarget target : targets.stream()
                        .limit(MAX_TARGETS_PER_CALL)
                        .toList()) {
                    edges.add(new CallEdge(
                            method.id(),
                            target.method().id(),
                            call.line(),
                            call.expression(),
                            target.resolution()
                    ));
                }
            }
            outgoing.put(method.id(), List.copyOf(edges));
        }
        return new CallGraph(Map.copyOf(outgoing), List.copyOf(unresolved));
    }

    private List<ResolvedTarget> resolveTargets(
            MethodNode caller,
            CallSite call,
            SourceIndex index
    ) {
        LinkedHashMap<String, ResolvedTarget> targets = new LinkedHashMap<>();
        String receiverType = call.receiverType();

        if (receiverType != null && !receiverType.isBlank()) {
            addClassTargets(
                    targets,
                    index,
                    receiverType,
                    call,
                    "receiver-type"
            );
            for (String implementation : index.implementations()
                    .getOrDefault(
                            AnalysisTextUtils.simpleName(receiverType),
                            Set.of()
                    )) {
                addClassTargets(
                        targets,
                        index,
                        implementation,
                        call,
                        "interface-implementation"
                );
            }
        }

        if (call.receiver().isBlank()
                || "this".equals(call.receiver())
                || "super".equals(call.receiver())) {
            addClassTargets(
                    targets,
                    index,
                    caller.className(),
                    call,
                    "same-class"
            );
        }
        if (targets.isEmpty()
                && AnalysisTextUtils.startsUppercase(call.receiver())) {
            addClassTargets(
                    targets,
                    index,
                    call.receiver(),
                    call,
                    "static-class-name"
            );
        }

        List<MethodNode> byName = index.methodsByName()
                .getOrDefault(call.methodName(), List.of());
        if (targets.isEmpty() && byName.size() == 1) {
            MethodNode target = byName.getFirst();
            targets.put(
                    target.id(),
                    new ResolvedTarget(target, "unique-method-name")
            );
        }
        return List.copyOf(targets.values());
    }

    private void addClassTargets(
            Map<String, ResolvedTarget> targets,
            SourceIndex index,
            String className,
            CallSite call,
            String resolution
    ) {
        String key = AnalysisTextUtils.simpleName(className)
                + "#" + call.methodName();
        List<MethodNode> candidates = index.methodsByClassAndName()
                .getOrDefault(key, List.of());
        List<MethodNode> arityMatches = candidates.stream()
                .filter(method ->
                        method.parameterCount() == call.argumentCount())
                .toList();
        List<MethodNode> effective = arityMatches.isEmpty()
                ? candidates
                : arityMatches;
        for (MethodNode target : effective) {
            targets.putIfAbsent(
                    target.id(),
                    new ResolvedTarget(target, resolution)
            );
        }
    }

    private record ResolvedTarget(MethodNode method, String resolution) { }
}
