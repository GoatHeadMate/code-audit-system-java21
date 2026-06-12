package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintFlow;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class TaintFlowVerifier {

    List<CandidatePath> verify(
            List<CandidatePath> candidates,
            Map<String, TaintSummary> summaries
    ) {
        List<CandidatePath> result = new ArrayList<>(candidates.size());
        for (CandidatePath candidate : candidates) {
            VerificationResult verification = verifyPath(candidate, summaries);
            result.add(new CandidatePath(
                    candidate.id(),
                    candidate.entryPoint(),
                    candidate.sink(),
                    candidate.methodPath(),
                    candidate.callEdges(),
                    candidate.staticConfidence(),
                    candidate.callDepth(),
                    candidate.reviewStatus(),
                    verification.confidence(),
                    verification.trace()
            ));
        }
        return List.copyOf(result);
    }

    private VerificationResult verifyPath(
            CandidatePath candidate,
            Map<String, TaintSummary> summaries
    ) {
        List<MethodStep> steps = candidate.methodPath();
        List<CallEdge> edges = candidate.callEdges();
        List<String> trace = new ArrayList<>();

        if (steps.isEmpty()) {
            return new VerificationResult("NONE", trace);
        }

        String entryMethodId = steps.getFirst().methodId();
        TaintSummary entrySummary = summaries.get(entryMethodId);

        Set<Integer> currentTaintedParams = new HashSet<>();
        if (entrySummary != null) {
            for (int i = 0; i < Math.max(4, entrySummary.parameterFlows().size() + 1); i++) {
                currentTaintedParams.add(i);
            }
        }
        currentTaintedParams.add(0);
        currentTaintedParams.add(1);
        currentTaintedParams.add(2);
        currentTaintedParams.add(3);

        trace.add("Entry: " + steps.getFirst().className() + "." + steps.getFirst().methodName()
                + " — all HTTP parameters are taint sources");

        boolean taintReachesSink = false;
        boolean hasStringPropagation = false;
        int taintedEdges = 0;

        for (int edgeIdx = 0; edgeIdx < edges.size(); edgeIdx++) {
            CallEdge edge = edges.get(edgeIdx);
            String fromMethodId = edge.fromMethodId();
            String toMethodId = edge.toMethodId();

            TaintSummary fromSummary = summaries.get(fromMethodId);
            if (fromSummary == null) {
                trace.add("Step " + (edgeIdx + 1) + ": " + abbreviate(fromMethodId)
                        + " → " + abbreviate(toMethodId)
                        + " [no taint summary, assumed propagated]");
                continue;
            }

            boolean edgeTainted = false;
            Set<Integer> nextTaintedParams = new HashSet<>();

            for (TaintFlow flow : fromSummary.parameterFlows()) {
                if (currentTaintedParams.contains(flow.sourceParamIndex())) {
                    edgeTainted = true;
                    nextTaintedParams.add(flow.targetArgIndex());

                    String propDesc = switch (flow.propagationType()) {
                        case "replace" -> "via String.replace() template substitution";
                        case "format" -> "via String.format()";
                        case "concatenation" -> "via string concatenation";
                        case "constructor-arg" -> "via constructor parameter";
                        default -> "via direct argument passing";
                    };

                    if ("replace".equals(flow.propagationType())
                            || "format".equals(flow.propagationType())) {
                        hasStringPropagation = true;
                    }

                    trace.add("Step " + (edgeIdx + 1) + ": param[" + flow.sourceParamIndex()
                            + "] of " + abbreviate(fromMethodId)
                            + " → arg[" + flow.targetArgIndex() + "] of "
                            + flow.targetCallMethodName()
                            + " " + propDesc);
                }
            }

            if (edgeTainted) {
                taintedEdges++;
                currentTaintedParams = nextTaintedParams;
            } else {
                if (fromSummary.hasTaintPropagation()) {
                    trace.add("Step " + (edgeIdx + 1) + ": "
                            + abbreviate(fromMethodId)
                            + " has taint propagation (replace/format), assumed flowing");
                    hasStringPropagation = true;
                } else {
                    trace.add("Step " + (edgeIdx + 1) + ": "
                            + abbreviate(fromMethodId)
                            + " → " + abbreviate(toMethodId)
                            + " [structural edge, no confirmed taint flow]");
                }
            }

            if (edgeIdx == edges.size() - 1) {
                TaintSummary sinkSummary = summaries.get(toMethodId);
                if (sinkSummary != null && sinkSummary.hasTaintPropagation()) {
                    taintReachesSink = true;
                    trace.add("Sink: " + abbreviate(toMethodId)
                            + " — tainted data reaches dangerous operation");
                } else if (!currentTaintedParams.isEmpty()) {
                    taintReachesSink = true;
                    trace.add("Sink: " + abbreviate(toMethodId)
                            + " — tainted parameters forwarded to sink method");
                }
            }
        }

        String confidence;
        if (taintReachesSink && hasStringPropagation) {
            confidence = "CONFIRMED";
        } else if (taintReachesSink || taintedEdges > edges.size() / 2) {
            confidence = "LIKELY";
        } else if (taintedEdges > 0) {
            confidence = "STRUCTURAL";
        } else {
            confidence = "STRUCTURAL";
        }

        return new VerificationResult(confidence, List.copyOf(trace));
    }

    private String abbreviate(String methodId) {
        int atIdx = methodId.indexOf('@');
        return atIdx > 0 ? methodId.substring(0, atIdx) : methodId;
    }

    private record VerificationResult(String confidence, List<String> trace) { }
}
