package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.EntryPointDiscoverer;
import com.huawei.audit.analysis.EntryPointDiscoverer.DiscoveredEntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.AnalysisResult;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageWritePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.TaintSummary;
import com.huawei.audit.analysis.impl.DangerousSinkClassifier.ExtraSinkRule;
import com.huawei.audit.process.ProcessRunner;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class WhiteBoxAnalysisServiceImpl implements WhiteBoxAnalysisService {
    private final List<EntryPointDiscoverer> entryPointDiscoverers;
    private final JavaSourceIndexer sourceIndexer;
    private final CallGraphBuilder callGraphBuilder;
    private final EntryPointBinder entryPointBinder;
    private final CandidatePathFinder candidatePathFinder;
    private final StorageWritePathFinder storageWritePathFinder;
    private final StoredCandidateCorrelator storedCandidateCorrelator;
    private final CoverageCalculator coverageCalculator;
    private final MyBatisXmlScanner myBatisXmlScanner;
    private final ConfigTemplateScanner configTemplateScanner;
    private final MethodTaintSummarizer taintSummarizer;
    private final TaintFlowVerifier taintFlowVerifier;
    private final TransitiveSinkResolver transitiveSinkResolver;

    public WhiteBoxAnalysisServiceImpl(
            List<EntryPointDiscoverer> entryPointDiscoverers
    ) {
        this.entryPointDiscoverers = List.copyOf(entryPointDiscoverers);
        this.sourceIndexer = new JavaSourceIndexer();
        this.callGraphBuilder = new CallGraphBuilder();
        this.entryPointBinder = new EntryPointBinder();
        this.candidatePathFinder = new CandidatePathFinder();
        this.storageWritePathFinder = new StorageWritePathFinder();
        this.storedCandidateCorrelator = new StoredCandidateCorrelator();
        this.coverageCalculator = new CoverageCalculator();
        this.myBatisXmlScanner = new MyBatisXmlScanner();
        this.configTemplateScanner = new ConfigTemplateScanner();
        this.taintSummarizer = new MethodTaintSummarizer();
        this.taintFlowVerifier = new TaintFlowVerifier();
        this.transitiveSinkResolver = new TransitiveSinkResolver();
    }

    @Override
    public AnalysisResult analyze(
            Path sourceRoot,
            List<Map<String, String>> dependencies,
            ProcessRunner processRunner,
            String claudeBin
    ) throws Exception {
        List<ExtraSinkRule> extraRules = new LlmSinkExpander().expand(
                dependencies, processRunner, claudeBin, sourceRoot
        );

        List<DiscoveredEntryPoint> discovered = new ArrayList<>();
        for (EntryPointDiscoverer discoverer : entryPointDiscoverers) {
            discovered.addAll(discoverer.discover(sourceRoot));
        }

        SourceIndex baseIndex = sourceIndexer.build(sourceRoot, extraRules);
        SourceIndex withMyBatis = baseIndex.withAdditionalSinks(
                myBatisXmlScanner.findSinks(sourceRoot, baseIndex)
        );
        SourceIndex sourceIndex = withMyBatis.withAdditionalSinks(
                configTemplateScanner.findSinks(sourceRoot, withMyBatis)
        );

        List<Sink> llmReviewedSinks = new SuspiciousCallReviewer().review(
                sourceIndex, processRunner, claudeBin, sourceRoot
        );
        SourceIndex finalIndex = sourceIndex.withAdditionalSinks(llmReviewedSinks);

        CallGraph callGraph = callGraphBuilder.build(finalIndex);

        List<Sink> transitiveSinks = transitiveSinkResolver.resolve(
                finalIndex, callGraph);
        SourceIndex enrichedIndex = finalIndex.withAdditionalSinks(transitiveSinks);

        List<EntryPoint> entryPoints = entryPointBinder.bind(
                discovered,
                enrichedIndex
        );
        List<CandidatePath> candidates = candidatePathFinder.find(
                entryPoints,
                enrichedIndex,
                callGraph
        );

        Map<String, TaintSummary> taintSummaries =
                taintSummarizer.summarizeAll(enrichedIndex.methods());
        List<CandidatePath> taintVerifiedCandidates =
                taintFlowVerifier.verify(candidates, taintSummaries);

        List<StorageWritePath> writePaths = storageWritePathFinder.find(
                entryPoints,
                enrichedIndex,
                callGraph
        );
        List<StoredCandidate> storedCandidates =
                storedCandidateCorrelator.correlate(
                        writePaths,
                        taintVerifiedCandidates,
                        enrichedIndex
                );
        return new AnalysisResult(
                entryPoints,
                enrichedIndex.sinks(),
                taintVerifiedCandidates,
                enrichedIndex.storageAccesses(),
                storedCandidates,
                callGraph.unresolvedCalls(),
                enrichedIndex.parseErrors(),
                coverageCalculator.calculate(
                        sourceRoot,
                        enrichedIndex,
                        callGraph,
                        entryPoints,
                        taintVerifiedCandidates,
                        storedCandidates,
                        extraRules.size(),
                        llmReviewedSinks.size()
                ),
                Map.copyOf(taintSummaries)
        );
    }
}
