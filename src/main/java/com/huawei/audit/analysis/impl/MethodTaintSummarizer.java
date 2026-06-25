package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.Assignment;
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

/**
 * Intra-procedural, flow-insensitive taint summary for one method.
 *
 * <p>Taint is propagated to a fixpoint over three expression-level forms captured
 * during indexing — assignments ({@code x = expr}), for-each bindings (modelled as
 * {@code v = iterable}), and mutating string-builder/propagator calls — so taint
 * reaches sinks through intermediate variables, helper-return values, and
 * {@code String.format}/{@code replace}/concat chains. {@code paramsThatReachReturn}
 * is computed from the real return expressions, not a signature string heuristic,
 * which lets a helper such as a {@code ${key}} template-substitution utility be
 * recognised as a taint-return propagator. All rules are language-level — no
 * project- or API-specific names.
 */
final class MethodTaintSummarizer {
    private static final int MAX_PASSES = 6;
    private static final Set<String> STRING_PROPAGATORS = Set.of(
            "replace", "replaceAll", "replaceFirst",
            "format", "formatted",
            "concat", "substring", "trim", "strip",
            "toLowerCase", "toUpperCase",
            "append", "insert", "toString",
            "split"
    );
    private static final Set<String> TAINT_PROPAGATOR_METHODS = Set.of(
            "replace", "replaceAll", "replaceFirst",
            "format", "formatted",
            "concat", "append", "insert",
            "split"
    );

    Map<String, TaintSummary> summarizeAll(List<MethodNode> methods) {
        Map<String, TaintSummary> result = new LinkedHashMap<>();
        for (MethodNode method : methods) {
            result.put(method.id(), summarize(method));
        }
        return Map.copyOf(result);
    }

    TaintSummary summarize(MethodNode method) {
        // variableName -> set of parameter indices whose taint reaches it.
        Map<String, Set<Integer>> variableTaint = new LinkedHashMap<>();
        for (int i = 0; i < method.parameterNames().size(); i++) {
            variableTaint
                    .computeIfAbsent(method.parameterNames().get(i), k -> new HashSet<>())
                    .add(i);
        }

        propagateToFixpoint(method, variableTaint);

        boolean hasStringManip = false;
        boolean hasTaintProp = false;
        List<TaintFlow> flows = new ArrayList<>();
        for (CallSite call : method.calls()) {
            List<String> argExprs = call.argumentExpressions() != null
                    ? call.argumentExpressions() : List.of();
            for (int argIdx = 0; argIdx < call.argumentCount(); argIdx++) {
                String argExpr = argIdx < argExprs.size() ? argExprs.get(argIdx) : "";
                if (argExpr.isBlank()) {
                    continue;
                }
                for (var taintEntry : variableTaint.entrySet()) {
                    if (taintEntry.getValue().isEmpty()
                            || !expressionReferencesVariable(argExpr, taintEntry.getKey())) {
                        continue;
                    }
                    String propType = inferPropagationType(
                            call.methodName(), call.expression());
                    for (int paramIdx : taintEntry.getValue()) {
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
            if (STRING_PROPAGATORS.contains(call.methodName())) {
                hasStringManip = true;
                if (callReferencesTaint(call, variableTaint)) {
                    hasTaintProp = true;
                }
            }
        }

        Set<Integer> paramsThatReachReturn = new HashSet<>();
        for (String returnExpr : method.returnExpressions()) {
            paramsThatReachReturn.addAll(paramsReferencedBy(returnExpr, variableTaint));
        }
        if (!paramsThatReachReturn.isEmpty()) {
            hasTaintProp = true;
        }

        return new TaintSummary(
                method.id(),
                List.copyOf(flows),
                Set.copyOf(paramsThatReachReturn),
                hasStringManip,
                hasTaintProp
        );
    }

    /**
     * Repeatedly apply assignment and mutating-call propagation until no new taint
     * is discovered (bounded by {@link #MAX_PASSES}). A bounded fixpoint is needed
     * because taint can flow forward then backward across statements (e.g. a loop
     * variable tainted by a collection, then used to mutate an accumulator).
     */
    private void propagateToFixpoint(
            MethodNode method,
            Map<String, Set<Integer>> variableTaint
    ) {
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            boolean changed = false;
            for (Assignment assignment : method.assignments()) {
                Set<Integer> refs = paramsReferencedBy(assignment.value(), variableTaint);
                if (!refs.isEmpty() && variableTaint
                        .computeIfAbsent(assignment.target(), k -> new HashSet<>())
                        .addAll(refs)) {
                    changed = true;
                }
            }
            for (CallSite call : method.calls()) {
                if (!TAINT_PROPAGATOR_METHODS.contains(call.methodName())) {
                    continue;
                }
                String receiver = call.receiver();
                if (receiver == null || receiver.isBlank()) {
                    continue;
                }
                Set<Integer> refs = callReferencesTaintParams(call, variableTaint);
                if (refs.isEmpty()) {
                    continue;
                }
                String root = receiver.split("[.\\[(]", 2)[0];
                if (variableTaint.computeIfAbsent(root, k -> new HashSet<>())
                        .addAll(refs)) {
                    changed = true;
                }
            }
            if (!changed) {
                return;
            }
        }
    }

    private Set<Integer> paramsReferencedBy(
            String expression,
            Map<String, Set<Integer>> variableTaint
    ) {
        Set<Integer> result = new HashSet<>();
        if (expression == null || expression.isBlank()) {
            return result;
        }
        for (var entry : variableTaint.entrySet()) {
            if (!entry.getValue().isEmpty()
                    && expressionReferencesVariable(expression, entry.getKey())) {
                result.addAll(entry.getValue());
            }
        }
        return result;
    }

    private Set<Integer> callReferencesTaintParams(
            CallSite call,
            Map<String, Set<Integer>> variableTaint
    ) {
        Set<Integer> result = new HashSet<>();
        List<String> argExprs = call.argumentExpressions() != null
                ? call.argumentExpressions() : List.of();
        for (String argExpr : argExprs) {
            result.addAll(paramsReferencedBy(argExpr, variableTaint));
        }
        return result;
    }

    private boolean callReferencesTaint(
            CallSite call,
            Map<String, Set<Integer>> variableTaint
    ) {
        if (!callReferencesTaintParams(call, variableTaint).isEmpty()) {
            return true;
        }
        String receiver = call.receiver();
        if (receiver == null || receiver.isBlank()) {
            return false;
        }
        String root = receiver.split("[.\\[(]", 2)[0];
        Set<Integer> receiverTaint = variableTaint.get(root);
        return receiverTaint != null && !receiverTaint.isEmpty();
    }

    private boolean expressionReferencesVariable(String expression, String varName) {
        if (expression == null || expression.isBlank() || varName.isBlank()) {
            return false;
        }
        return Pattern.compile("\\b" + Pattern.quote(varName) + "\\b")
                .matcher(expression)
                .find();
    }

    private String inferPropagationType(String methodName, String expression) {
        if (Set.of("replace", "replaceAll", "replaceFirst").contains(methodName)) {
            if (expression != null && expression.contains("${")) {
                return "template-substitution";
            }
            return "replace";
        }
        if (Set.of("format", "formatted").contains(methodName)) {
            return "format";
        }
        if (Set.of("append", "insert", "concat").contains(methodName)) {
            return "concatenation";
        }
        if ("split".equals(methodName)) {
            return "split";
        }
        if ("<init>".equals(methodName)) {
            return "constructor-arg";
        }
        return "direct";
    }
}
