package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.EntryPointDiscoverer.DiscoveredEntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

final class EntryPointBinder {
    List<EntryPoint> bind(
            List<DiscoveredEntryPoint> endpoints,
            SourceIndex index
    ) {
        List<EntryPoint> result = new ArrayList<>();
        int sequence = 1;
        for (DiscoveredEntryPoint endpoint : endpoints) {
            Optional<MethodNode> method = index.methods().stream()
                    .filter(candidate ->
                            candidate.filePath().equals(endpoint.filePath()))
                    .filter(candidate ->
                            candidate.methodName().equals(endpoint.methodName()))
                    .min(Comparator.comparingInt(candidate ->
                            Math.abs(
                                    candidate.startLine()
                                            - endpoint.startLine()
                            )));
            result.add(new EntryPoint(
                    "entry-" + sequence++,
                    endpoint.protocol(),
                    endpoint.operations(),
                    endpoint.route(),
                    endpoint.className(),
                    endpoint.methodName(),
                    endpoint.filePath(),
                    endpoint.startLine(),
                    endpoint.framework(),
                    endpoint.securityAnnotations(),
                    endpoint.discoverySource(),
                    endpoint.confidence(),
                    method.map(MethodNode::id).orElse(""),
                    method.isPresent() ? "BOUND" : "UNRESOLVED"
            ));
        }
        return List.copyOf(result);
    }
}
