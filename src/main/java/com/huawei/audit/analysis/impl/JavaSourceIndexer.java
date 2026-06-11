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
    SourceIndex build(Path sourceRoot) throws Exception {
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

        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(
                null,
                Locale.ROOT,
                StandardCharsets.UTF_8
        )) {
            JavacTask task = (JavacTask) compiler.getTask(
                    null,
                    fileManager,
                    diagnostic -> parseErrors.add(diagnostic.toString()),
                    List.of("-proc:none", "-Xlint:none"),
                    null,
                    fileManager.getJavaFileObjectsFromPaths(sourceFiles)
            );
            Iterable<? extends CompilationUnitTree> units = task.parse();
            SourcePositions positions = Trees.instance(task).getSourcePositions();
            AtomicInteger methodSequence = new AtomicInteger();

            for (CompilationUnitTree unit : units) {
                Path file = Path.of(unit.getSourceFile().toUri());
                new CompilationUnitIndexer(
                        unit,
                        positions,
                        AnalysisTextUtils.relativePath(sourceRoot, file),
                        Files.readString(file),
                        methods,
                        sinks,
                        implementations,
                        methodSequence
                ).scan(unit, null);
            }
        }
        return SourceIndex.create(methods, sinks, implementations, parseErrors);
    }
}
