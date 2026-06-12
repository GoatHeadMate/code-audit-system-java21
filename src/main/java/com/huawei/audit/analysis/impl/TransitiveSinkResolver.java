package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class TransitiveSinkResolver {

    List<Sink> resolve(SourceIndex index, CallGraph callGraph) {
        Set<String> existingSinkMethodIds = new LinkedHashSet<>();
        Map<String, String> sinkCategoryByMethodId = new LinkedHashMap<>();
        for (Sink sink : index.sinks()) {
            existingSinkMethodIds.add(sink.methodId());
            sinkCategoryByMethodId.put(sink.methodId(), sink.category());
        }

        List<Sink> derivedSinks = new ArrayList<>();
        int sequence = index.sinks().size();

        for (MethodNode method : index.methods()) {
            if (existingSinkMethodIds.contains(method.id())) {
                continue;
            }

            List<CallEdge> edges = callGraph.outgoing()
                    .getOrDefault(method.id(), List.of());

            for (CallEdge edge : edges) {
                String targetId = edge.toMethodId();
                String category = sinkCategoryByMethodId.get(targetId);
                if (category == null) {
                    continue;
                }

                if (!forwardsParameter(method, edge)) {
                    continue;
                }

                sequence++;
                derivedSinks.add(new Sink(
                        "sink-derived-" + sequence,
                        category,
                        "transitive:" + abbreviate(targetId),
                        method.id(),
                        method.filePath(),
                        edge.line(),
                        edge.expression()
                ));
                existingSinkMethodIds.add(method.id());
                sinkCategoryByMethodId.put(method.id(), category);
                break;
            }
        }

        return List.copyOf(derivedSinks);
    }

    private boolean forwardsParameter(MethodNode method, CallEdge edge) {
        if (method.parameterCount() == 0) {
            return false;
        }
        for (CallSite call : method.calls()) {
            if (call.line() == edge.line() && call.argumentCount() > 0) {
                String expression = call.expression() != null ? call.expression() : "";
                for (String paramName : method.parameterNames()) {
                    if (expression.contains(paramName)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private String abbreviate(String methodId) {
        int atIdx = methodId.indexOf('@');
        return atIdx > 0 ? methodId.substring(0, atIdx) : methodId;
    }
}
