package com.huawei.audit.analysis;

import com.huawei.audit.agent.ClaudeGateway;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface WhiteBoxAnalysisService {
    AnalysisResult analyze(
            Path sourceRoot,
            List<Map<String, String>> dependencies,
            ClaudeGateway claudeGateway
    ) throws Exception;

    record EntryPoint(
            String id,
            String protocol,
            List<String> httpMethods,
            String path,
            String className,
            String methodName,
            String filePath,
            int startLine,
            String framework,
            List<String> securityAnnotations,
            String discoverySource,
            String discoveryConfidence,
            String methodId,
            String bindingStatus
    ) { }

    record Sink(
            String id,
            String category,
            String api,
            String methodId,
            String filePath,
            int line,
            String code
    ) { }

    record MethodNode(
            String id,
            String className,
            String methodName,
            int parameterCount,
            List<String> parameterNames,
            String filePath,
            int startLine,
            int endLine,
            String signature,
            List<CallSite> calls,
            Map<String, String> variableTypes,
            List<String> methodReferences,
            List<StorageAccess> storageAccesses
    ) { }

    record CallSite(
            String methodName,
            String receiver,
            String receiverType,
            int argumentCount,
            List<String> argumentTypes,
            List<String> argumentExpressions,
            int line,
            String expression
    ) { }

    record CallEdge(
            String fromMethodId,
            String toMethodId,
            int line,
            String expression,
            String resolution
    ) { }

    record MethodStep(
            String methodId,
            String className,
            String methodName,
            String filePath,
            int startLine,
            int endLine,
            String signature
    ) { }

    record CandidatePath(
            String id,
            EntryPoint entryPoint,
            Sink sink,
            List<MethodStep> methodPath,
            List<CallEdge> callEdges,
            String staticConfidence,
            int callDepth,
            String reviewStatus,
            String taintConfidence,
            List<String> taintTrace,
            String sourceClassification
    ) { }

    record StorageAccess(
            String id,
            String kind,
            String storageKey,
            String receiverType,
            String operation,
            String methodId,
            String filePath,
            int line,
            String expression,
            String valueType
    ) { }

    record StorageWritePath(
            EntryPoint entryPoint,
            StorageAccess writeAccess,
            List<MethodStep> methodPath,
            List<CallEdge> callEdges,
            String staticConfidence
    ) { }

    record StoredCandidate(
            String id,
            String storageKey,
            StorageWritePath writePath,
            CandidatePath executionPath,
            StorageAccess readAccess,
            String correlationConfidence,
            String reviewStatus
    ) { }

    record UnresolvedCall(
            String callerMethodId,
            String filePath,
            int line,
            String expression
    ) { }

    record Coverage(
            long javaFiles,
            long parsedMethods,
            long discoveredEntryPoints,
            long boundEntryPoints,
            long unresolvedEntryPoints,
            long dangerousSinks,
            long candidatePaths,
            long storageAccesses,
            long storedCandidates,
            long entryPointsReachingSink,
            long unresolvedCalls,
            long parserDiagnostics,
            double entryBindingRate,
            Map<String, Long> entryPointsByDiscoverer,
            Map<String, Long> sinksByCategory,
            Map<String, Long> candidatePathsBySink,
            long llmExpandedRules,
            long llmReviewedSinks
    ) { }

    record TaintFlow(
            int sourceParamIndex,
            String targetCallMethodName,
            String targetCallReceiver,
            int targetArgIndex,
            String propagationType
    ) { }

    record TaintSummary(
            String methodId,
            List<TaintFlow> parameterFlows,
            Set<Integer> paramsThatReachReturn,
            boolean hasStringManipulation,
            boolean hasTaintPropagation
    ) { }

    record AnalysisResult(
            List<EntryPoint> entryPoints,
            List<Sink> sinks,
            List<CandidatePath> candidatePaths,
            List<StorageAccess> storageAccesses,
            List<StoredCandidate> storedCandidates,
            List<UnresolvedCall> unresolvedCalls,
            List<String> parserDiagnostics,
            Coverage coverage,
            Map<String, TaintSummary> taintSummaries
    ) { }
}
