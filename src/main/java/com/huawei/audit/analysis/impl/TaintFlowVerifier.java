package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodStep;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintFlow;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
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
                    verification.trace(),
                    verification.sourceClassification()
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
            return new VerificationResult("NONE", trace, "UNKNOWN");
        }

        String entryMethodId = steps.getFirst().methodId();
        TaintSummary entrySummary = summaries.get(entryMethodId);
        String protocol = candidate.entryPoint() != null
                ? candidate.entryPoint().protocol() : "";
        int declaredParamCount = steps.getFirst().parameterCount();

        Set<Integer> currentTaintedParams = new HashSet<>();
        String sourceDesc;
        if (isExternalProtocol(protocol)) {
            for (int i = 0; i < declaredParamCount; i++) {
                currentTaintedParams.add(i);
            }
            sourceDesc = declaredParamCount == 0
                    ? protocol + " entry has no declared parameters"
                    : protocol + " parameters [0.." + (declaredParamCount - 1)
                            + "] are taint sources";
        } else if (isInternalProtocol(protocol)) {
            sourceDesc = protocol + " entry — no external taint sources";
        } else {
            for (int i = 0; i < declaredParamCount; i++) {
                currentTaintedParams.add(i);
            }
            sourceDesc = "unknown protocol — conservatively marking "
                    + currentTaintedParams.size() + " params as tainted";
        }

        trace.add("Entry: " + steps.getFirst().className() + "."
                + steps.getFirst().methodName() + " — " + sourceDesc);

        boolean taintReachesSink = false;
        boolean hasStringPropagation = false;
        int taintedEdges = 0;
        if (isExternalProtocol(protocol)
                && entrySummary != null
                && flowTargetsSink(
                        entrySummary,
                        currentTaintedParams,
                        candidate
                )) {
            taintReachesSink = true;
            trace.add("Sink: " + abbreviate(entryMethodId)
                    + " — entry parameter reaches dangerous operation");
        }

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
                        case "template-substitution" ->
                                "via ${...} template substitution into command/query text";
                        case "replace" -> "via String.replace() template substitution";
                        case "format" -> "via String.format()";
                        case "concatenation" -> "via string concatenation";
                        case "split" -> "via String.split() preserving taint in array elements";
                        case "constructor-arg" -> "via constructor parameter";
                        default -> "via direct argument passing";
                    };

                    if ("template-substitution".equals(flow.propagationType())
                            || "replace".equals(flow.propagationType())
                            || "format".equals(flow.propagationType())
                            || "split".equals(flow.propagationType())) {
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
                if (edgeTainted
                        && sinkSummary != null
                        && sinkSummary.hasTaintPropagation()) {
                    taintReachesSink = true;
                    trace.add("Sink: " + abbreviate(toMethodId)
                            + " — tainted data reaches dangerous operation");
                } else if (edgeTainted && !nextTaintedParams.isEmpty()) {
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

        String sourceClassification = classifySource(
                protocol,
                candidate,
                taintReachesSink
        );
        return new VerificationResult(confidence, List.copyOf(trace), sourceClassification);
    }

    private static String classifySource(
            String protocol,
            CandidatePath candidate,
            boolean externalTaintObserved
    ) {
        if (candidate.entryPoint() != null) {
            String framework = candidate.entryPoint().framework();
            if (framework != null && framework.toLowerCase().contains("config")) {
                return "CONFIG_CONTROLLED";
            }
        }
        if (isExternalProtocol(protocol)) {
            return externalTaintObserved ? "REQUEST_CONTROLLED" : "UNKNOWN";
        }
        if (isInternalProtocol(protocol)) {
            return "INTERNAL_DERIVED";
        }
        return "UNKNOWN";
    }

    private String abbreviate(String methodId) {
        int atIdx = methodId.indexOf('@');
        return atIdx > 0 ? methodId.substring(0, atIdx) : methodId;
    }

    private static boolean isExternalProtocol(String protocol) {
        return "HTTP".equalsIgnoreCase(protocol)
                || "MESSAGE".equalsIgnoreCase(protocol)
                || "WEBSOCKET".equalsIgnoreCase(protocol);
    }

    private static boolean isInternalProtocol(String protocol) {
        return "LIFECYCLE".equalsIgnoreCase(protocol)
                || "SCHEDULED".equalsIgnoreCase(protocol)
                || "INIT".equalsIgnoreCase(protocol)
                || "EVENT".equalsIgnoreCase(protocol)
                || "ASYNC".equalsIgnoreCase(protocol);
    }

    private static boolean flowTargetsSink(
            TaintSummary summary,
            Set<Integer> taintedParams,
            CandidatePath candidate
    ) {
        String sinkText = (candidate.sink().api() + " "
                + candidate.sink().code()).toLowerCase(Locale.ROOT);
        return summary.parameterFlows().stream()
                .filter(flow -> taintedParams.contains(flow.sourceParamIndex()))
                .anyMatch(flow -> {
                    if ("<init>".equals(flow.targetCallMethodName())) {
                        String targetType = flow.targetCallReceiver();
                        return targetType != null
                                && !targetType.isBlank()
                                && sinkText.contains(
                                        "new " + targetType.toLowerCase(
                                                Locale.ROOT
                                        )
                                );
                    }
                    return sinkText.contains(
                            flow.targetCallMethodName().toLowerCase(
                                    Locale.ROOT
                            )
                    );
                });
    }

    private record VerificationResult(
            String confidence, List<String> trace, String sourceClassification) { }
}
