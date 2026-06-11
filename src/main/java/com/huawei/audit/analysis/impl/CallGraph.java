package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallEdge;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.UnresolvedCall;
import java.util.List;
import java.util.Map;

record CallGraph(
        Map<String, List<CallEdge>> outgoing,
        List<UnresolvedCall> unresolvedCalls
) { }
