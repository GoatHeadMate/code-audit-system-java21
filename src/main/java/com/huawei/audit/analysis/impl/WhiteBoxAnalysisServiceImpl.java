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
        List<EntryPoint> entryPoints = entryPointBinder.bind(
                discovered,
                finalIndex
        );
        List<CandidatePath> candidates = candidatePathFinder.find(
                entryPoints,
                finalIndex,
                callGraph
        );

        Map<String, TaintSummary> taintSummaries =
                taintSummarizer.summarizeAll(finalIndex.methods());
        List<CandidatePath> taintVerifiedCandidates =
                taintFlowVerifier.verify(candidates, taintSummaries);

        List<StorageWritePath> writePaths = storageWritePathFinder.find(
                entryPoints,
                finalIndex,
                callGraph
        );
        List<StoredCandidate> storedCandidates =
                storedCandidateCorrelator.correlate(
                        writePaths,
                        taintVerifiedCandidates,
                        finalIndex
                );
        return new AnalysisResult(
                entryPoints,
                finalIndex.sinks(),
                taintVerifiedCandidates,
                finalIndex.storageAccesses(),
                storedCandidates,
                callGraph.unresolvedCalls(),
                finalIndex.parseErrors(),
                coverageCalculator.calculate(
                        sourceRoot,
                        finalIndex,
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
