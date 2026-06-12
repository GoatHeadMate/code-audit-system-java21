package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.Trees;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

final class JavaSourceIndexer {
    private static final int SOURCE_BATCH_SIZE = 128;
    private static final int MAX_PARSE_ERRORS = 1_000;

    SourceIndex build(Path sourceRoot, List<DangerousSinkClassifier.ExtraSinkRule> extraRules) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException(
                    "JDK compiler is required for white-box source analysis"
            );
        }

        List<Path> sourceFiles;
        try (var paths = Files.walk(sourceRoot)) {
            sourceFiles = paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".java"))
                    .sorted()
                    .toList();
        }
        if (sourceFiles.isEmpty()) {
            return SourceIndex.empty();
        }

        List<MethodNode> methods = new ArrayList<>();
        List<Sink> sinks = new ArrayList<>();
        Map<String, Set<String>> implementations = new LinkedHashMap<>();
        List<String> parseErrors = new ArrayList<>();
        AtomicInteger methodSequence = new AtomicInteger();

        for (int start = 0; start < sourceFiles.size();
                start += SOURCE_BATCH_SIZE) {
            int end = Math.min(start + SOURCE_BATCH_SIZE, sourceFiles.size());
            indexBatch(
                    compiler,
                    sourceRoot,
                    sourceFiles.subList(start, end),
                    methods,
                    sinks,
                    implementations,
                    parseErrors,
                    methodSequence,
                    extraRules
            );
        }
        List<Sink> taintSinks = new MethodTaintAnalyzer().findTaintSinks(
                methods, sinks
        );
        sinks.addAll(taintSinks);
        return SourceIndex.create(methods, sinks, implementations, parseErrors);
    }

    private void indexBatch(
            JavaCompiler compiler,
            Path sourceRoot,
            List<Path> sourceFiles,
            List<MethodNode> methods,
            List<Sink> sinks,
            Map<String, Set<String>> implementations,
            List<String> parseErrors,
            AtomicInteger methodSequence,
            List<DangerousSinkClassifier.ExtraSinkRule> extraRules
    ) throws Exception {
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(
                null,
                Locale.ROOT,
                StandardCharsets.UTF_8
        )) {
            JavacTask task = (JavacTask) compiler.getTask(
                    null,
                    fileManager,
                    diagnostic -> {
                        if (parseErrors.size() < MAX_PARSE_ERRORS) {
                            parseErrors.add(diagnostic.toString());
                        }
                    },
                    List.of("-proc:none", "-Xlint:none"),
                    null,
                    fileManager.getJavaFileObjectsFromPaths(sourceFiles)
            );
            Iterable<? extends CompilationUnitTree> units = task.parse();
            SourcePositions positions = Trees.instance(task).getSourcePositions();
            for (CompilationUnitTree unit : units) {
                indexUnit(
                        sourceRoot,
                        unit,
                        positions,
                        methods,
                        sinks,
                        implementations,
                        methodSequence,
                        extraRules
                );
            }
        }
    }

    private void indexUnit(
            Path sourceRoot,
            CompilationUnitTree unit,
            SourcePositions positions,
            List<MethodNode> methods,
            List<Sink> sinks,
            Map<String, Set<String>> implementations,
            AtomicInteger methodSequence,
            List<DangerousSinkClassifier.ExtraSinkRule> extraRules
    ) throws Exception {
        Path file = Path.of(unit.getSourceFile().toUri());
        new CompilationUnitIndexer(
                unit,
                positions,
                AnalysisTextUtils.relativePath(sourceRoot, file),
                Files.readString(file),
                methods,
                sinks,
                implementations,
                methodSequence,
                extraRules
        ).scan(unit, null);
    }
}
