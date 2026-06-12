package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintFlow;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

final class MethodTaintSummarizer {
    private static final Set<String> STRING_PROPAGATORS = Set.of(
            "replace", "replaceAll", "replaceFirst",
            "format", "formatted",
            "concat", "substring", "trim", "strip",
            "toLowerCase", "toUpperCase",
            "append", "insert", "toString"
    );
    private static final Set<String> TAINT_PROPAGATOR_METHODS = Set.of(
            "replace", "replaceAll", "replaceFirst",
            "format", "formatted",
            "append"
    );

    Map<String, TaintSummary> summarizeAll(List<MethodNode> methods) {
        Map<String, TaintSummary> result = new LinkedHashMap<>();
        for (MethodNode method : methods) {
            result.put(method.id(), summarize(method));
        }
        return Map.copyOf(result);
    }

    TaintSummary summarize(MethodNode method) {
        Map<String, Integer> paramIndices = new LinkedHashMap<>();
        for (int i = 0; i < method.parameterNames().size(); i++) {
            paramIndices.put(method.parameterNames().get(i), i);
        }

        Map<String, Set<Integer>> variableTaint = new LinkedHashMap<>();
        for (var entry : paramIndices.entrySet()) {
            variableTaint.computeIfAbsent(entry.getKey(), k -> new HashSet<>())
                    .add(entry.getValue());
        }

        List<TaintFlow> flows = new ArrayList<>();
        boolean hasStringManip = false;
        boolean hasTaintProp = false;

        for (CallSite call : method.calls()) {
            String expression = call.expression() != null ? call.expression() : "";

            for (int argIdx = 0; argIdx < call.argumentTypes().size(); argIdx++) {
                for (var taintEntry : variableTaint.entrySet()) {
                    String varName = taintEntry.getKey();
                    if (expressionReferencesVariable(expression, varName)) {
                        for (int paramIdx : taintEntry.getValue()) {
                            String propType = inferPropagationType(call.methodName());
                            flows.add(new TaintFlow(
                                    paramIdx,
                                    call.methodName(),
                                    call.receiver(),
                                    argIdx,
                                    propType
                            ));
                        }
                    }
                }
            }

            if (STRING_PROPAGATORS.contains(call.methodName())) {
                hasStringManip = true;
                String receiver = call.receiver();
                if (receiver != null) {
                    String rootVar = receiver.split("[.\\[(]", 2)[0];
                    Set<Integer> receiverTaint = variableTaint.get(rootVar);
                    if (receiverTaint != null && !receiverTaint.isEmpty()) {
                        hasTaintProp = true;
                    }
                }
                if (TAINT_PROPAGATOR_METHODS.contains(call.methodName())) {
                    for (var taintEntry : variableTaint.entrySet()) {
                        if (expression.contains(taintEntry.getKey())
                                && !taintEntry.getValue().isEmpty()) {
                            hasTaintProp = true;
                            if (receiver != null && !receiver.isBlank()) {
                                String rootReceiver = receiver.split("[.\\[(]", 2)[0];
                                variableTaint.computeIfAbsent(rootReceiver, k -> new HashSet<>())
                                        .addAll(taintEntry.getValue());
                            }
                        }
                    }
                }
            }
        }

        Set<Integer> paramsThatReachReturn = new HashSet<>();
        String signature = method.signature() != null ? method.signature() : "";
        for (var entry : variableTaint.entrySet()) {
            if (!entry.getValue().isEmpty() && signature.contains(entry.getKey())) {
                paramsThatReachReturn.addAll(entry.getValue());
            }
        }

        return new TaintSummary(
                method.id(),
                List.copyOf(flows),
                Set.copyOf(paramsThatReachReturn),
                hasStringManip,
                hasTaintProp
        );
    }

    private boolean expressionReferencesVariable(String expression, String varName) {
        if (expression == null || expression.isBlank()) {
            return false;
        }
        return Pattern.compile("\\b" + Pattern.quote(varName) + "\\b")
                .matcher(expression)
                .find();
    }

    private String inferPropagationType(String methodName) {
        if (Set.of("replace", "replaceAll", "replaceFirst").contains(methodName)) {
            return "replace";
        }
        if (Set.of("format", "formatted").contains(methodName)) {
            return "format";
        }
        if ("append".equals(methodName)) {
            return "concatenation";
        }
        if ("<init>".equals(methodName)) {
            return "constructor-arg";
        }
        return "direct";
    }
}
