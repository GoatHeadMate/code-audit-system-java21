package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.UnresolvedCall;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class CallGraphBuilder {
    private static final int MAX_TARGETS_PER_CALL = 12;
    private static final Set<String> DEFERRED_DISPATCH_METHODS = Set.of(
            "execute",
            "invokeAndWait",
            "invokeLater",
            "runAsync",
            "schedule",
            "scheduleAtFixedRate",
            "scheduleWithFixedDelay",
            "submit",
            "supplyAsync",
            "register",
            "registerTask",
            "addTask",
            "enqueue",
            "offer",
            "post"
    );
    private static final Set<String> FUNCTIONAL_DISPATCH_METHODS = Set.of(
            "accept",
            "apply",
            "call",
            "run",
            "test"
    );
    private static final Set<String> FUNCTIONAL_TYPES = Set.of(
            "BiConsumer",
            "BiFunction",
            "Callable",
            "Consumer",
            "Function",
            "Predicate",
            "Runnable",
            "Supplier"
    );

    CallGraph build(SourceIndex index) {
        Map<String, List<CallEdge>> outgoing = new LinkedHashMap<>();
        List<UnresolvedCall> unresolved = new ArrayList<>();
        Map<String, List<String>> referencesByClass =
                methodReferencesByClass(index);
        Map<String, Set<String>> implementations =
                ImplementationIndex.transitive(index.implementations());

        for (MethodNode method : index.methods()) {
            List<CallEdge> edges = new ArrayList<>();
            for (CallSite call : method.calls()) {
                List<ResolvedTarget> targets = resolveTargets(
                        method,
                        call,
                        index,
                        implementations
                );
                List<ResolvedTarget> callbacks = resolveCallbacks(
                        method,
                        call,
                        index,
                        referencesByClass
                );
                LinkedHashMap<String, ResolvedTarget> resolved =
                        new LinkedHashMap<>();
                targets.forEach(target ->
                        resolved.putIfAbsent(target.method().id(), target));
                callbacks.forEach(target ->
                        resolved.putIfAbsent(target.method().id(), target));
                if (resolved.isEmpty()) {
                    unresolved.add(new UnresolvedCall(
                            method.id(),
                            method.filePath(),
                            call.line(),
                            call.expression()
                    ));
                    continue;
                }
                for (ResolvedTarget target : resolved.values().stream()
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
            SourceIndex index,
            Map<String, Set<String>> implementations
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
            for (String implementation : implementations
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

        if (targets.isEmpty()
                && !call.receiver().isBlank()
                && !"this".equals(call.receiver())
                && !"super".equals(call.receiver())
                && !call.receiver().contains("(")
                && Character.isLowerCase(call.receiver().charAt(0))) {
            String inferredType = Character.toUpperCase(
                    call.receiver().charAt(0))
                    + call.receiver().substring(1);
            addClassTargets(
                    targets,
                    index,
                    inferredType,
                    call,
                    "field-name-type"
            );
            for (String impl : implementations.getOrDefault(
                    inferredType,
                    Set.of()
            )) {
                addClassTargets(
                        targets,
                        index,
                        impl,
                        call,
                        "field-name-type"
                );
            }
        }

        List<MethodNode> byName = index.methodsByName()
                .getOrDefault(call.methodName(), List.of())
                .stream()
                .filter(method ->
                        method.parameterCount() == call.argumentCount())
                .toList();
        if (targets.isEmpty() && byName.size() == 1) {
            MethodNode target = byName.getFirst();
            targets.put(
                    target.id(),
                    new ResolvedTarget(target, "unique-method-name")
            );
        }
        return List.copyOf(targets.values());
    }

    private List<ResolvedTarget> resolveCallbacks(
            MethodNode caller,
            CallSite call,
            SourceIndex index,
            Map<String, List<String>> referencesByClass
    ) {
        LinkedHashMap<String, ResolvedTarget> targets = new LinkedHashMap<>();
        if (DEFERRED_DISPATCH_METHODS.contains(call.methodName())) {
            for (String argumentType : call.argumentTypes()) {
                if (argumentType == null || argumentType.isBlank()) {
                    continue;
                }
                addCallbackMethod(
                        targets,
                        index,
                        argumentType,
                        "run",
                        "deferred-callback"
                );
                addCallbackMethod(
                        targets,
                        index,
                        argumentType,
                        "call",
                        "deferred-callback"
                );
            }
        }
        if (targets.isEmpty()) {
            for (String argumentType : call.argumentTypes()) {
                if (argumentType == null || argumentType.isBlank()) {
                    continue;
                }
                String simpleName = AnalysisTextUtils.simpleName(
                        argumentType);
                if (!index.methodsByClassAndName()
                        .getOrDefault(simpleName + "#run", List.of())
                        .isEmpty()) {
                    addCallbackMethod(
                            targets,
                            index,
                            argumentType,
                            "run",
                            "runnable-arg-callback"
                    );
                }
                if (!index.methodsByClassAndName()
                        .getOrDefault(simpleName + "#call", List.of())
                        .isEmpty()) {
                    addCallbackMethod(
                            targets,
                            index,
                            argumentType,
                            "call",
                            "runnable-arg-callback"
                    );
                }
            }
        }
        if (isFunctionalDispatch(call)) {
            for (String reference : referencesByClass.getOrDefault(
                    caller.className(),
                    List.of()
            )) {
                addCallbackMethod(
                        targets,
                        index,
                        caller.className(),
                        reference,
                        "functional-method-reference"
                );
            }
        }
        return List.copyOf(targets.values());
    }

    private Map<String, List<String>> methodReferencesByClass(
            SourceIndex index
    ) {
        Map<String, LinkedHashSet<String>> collected = new LinkedHashMap<>();
        for (MethodNode method : index.methods()) {
            if (method.methodReferences().isEmpty()) {
                continue;
            }
            collected.computeIfAbsent(
                    method.className(),
                    ignored -> new LinkedHashSet<>()
            ).addAll(method.methodReferences());
        }
        Map<String, List<String>> result = new LinkedHashMap<>();
        collected.forEach((className, references) ->
                result.put(className, List.copyOf(references)));
        return Map.copyOf(result);
    }

    private boolean isFunctionalDispatch(CallSite call) {
        if (!FUNCTIONAL_DISPATCH_METHODS.contains(call.methodName())) {
            return false;
        }
        String receiverType = AnalysisTextUtils.simpleName(
                call.receiverType()
        );
        return FUNCTIONAL_TYPES.contains(receiverType)
                || call.receiver().contains("(");
    }

    private void addCallbackMethod(
            Map<String, ResolvedTarget> targets,
            SourceIndex index,
            String className,
            String methodName,
            String resolution
    ) {
        String key = AnalysisTextUtils.simpleName(className)
                + "#" + methodName;
        for (MethodNode target : index.methodsByClassAndName()
                .getOrDefault(key, List.of())) {
            targets.putIfAbsent(
                    target.id(),
                    new ResolvedTarget(target, resolution)
            );
        }
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
        for (MethodNode target : arityMatches) {
            targets.putIfAbsent(
                    target.id(),
                    new ResolvedTarget(target, resolution)
            );
        }
    }

    private record ResolvedTarget(MethodNode method, String resolution) { }
}
