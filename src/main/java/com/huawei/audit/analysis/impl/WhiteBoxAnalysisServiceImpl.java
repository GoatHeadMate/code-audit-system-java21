package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.EntryPointDiscoverer;
import com.huawei.audit.analysis.EntryPointDiscoverer.DiscoveredEntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.AnalysisResult;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CandidatePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.EntryPoint;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageWritePath;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StoredCandidate;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
    }

    @Override
    public AnalysisResult analyze(Path sourceRoot) throws Exception {
        List<DiscoveredEntryPoint> discovered = new ArrayList<>();
        for (EntryPointDiscoverer discoverer : entryPointDiscoverers) {
            discovered.addAll(discoverer.discover(sourceRoot));
        }

        SourceIndex baseIndex = sourceIndexer.build(sourceRoot);
        SourceIndex sourceIndex = baseIndex.withAdditionalSinks(
                myBatisXmlScanner.findSinks(sourceRoot, baseIndex)
        );
        CallGraph callGraph = callGraphBuilder.build(sourceIndex);
        List<EntryPoint> entryPoints = entryPointBinder.bind(
                discovered,
                sourceIndex
        );
        List<CandidatePath> candidates = candidatePathFinder.find(
                entryPoints,
                sourceIndex,
                callGraph
        );
        List<StorageWritePath> writePaths = storageWritePathFinder.find(
                entryPoints,
                sourceIndex,
                callGraph
        );
        List<StoredCandidate> storedCandidates =
                storedCandidateCorrelator.correlate(
                        writePaths,
                        candidates,
                        sourceIndex
                );
        return new AnalysisResult(
                entryPoints,
                sourceIndex.sinks(),
                candidates,
                sourceIndex.storageAccesses(),
                storedCandidates,
                callGraph.unresolvedCalls(),
                sourceIndex.parseErrors(),
                coverageCalculator.calculate(
                        sourceRoot,
                        sourceIndex,
                        callGraph,
                        entryPoints,
                        candidates,
                        storedCandidates
                )
        );
    }
}
