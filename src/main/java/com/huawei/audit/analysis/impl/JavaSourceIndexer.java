package com.huawei.audit.analysis.impl;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

final class JavaSourceIndexer {
    private static final int MAX_PARSE_ERRORS = 1_000;

    SourceIndex build(
            Path sourceRoot,
            List<DangerousSinkClassifier.ExtraSinkRule> extraRules
    ) throws Exception {
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

        JavaParser parser = new JavaParser(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));

        for (Path file : sourceFiles) {
            indexFile(
                    parser,
                    sourceRoot,
                    file,
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

    private void indexFile(
            JavaParser parser,
            Path sourceRoot,
            Path file,
            List<MethodNode> methods,
            List<Sink> sinks,
            Map<String, Set<String>> implementations,
            List<String> parseErrors,
            AtomicInteger methodSequence,
            List<DangerousSinkClassifier.ExtraSinkRule> extraRules
    ) {
        ParseResult<CompilationUnit> result;
        try {
            result = parser.parse(file);
        } catch (Exception exception) {
            recordError(parseErrors, file + ": " + exception.getMessage());
            return;
        }
        for (var problem : result.getProblems()) {
            recordError(parseErrors, problem.toString());
        }
        if (result.getResult().isEmpty()) {
            return;
        }
        CompilationUnit unit = result.getResult().get();
        unit.accept(
                new CompilationUnitIndexer(
                        AnalysisTextUtils.relativePath(sourceRoot, file),
                        methods,
                        sinks,
                        implementations,
                        methodSequence,
                        extraRules
                ),
                null
        );
    }

    private void recordError(List<String> parseErrors, String message) {
        if (parseErrors.size() < MAX_PARSE_ERRORS) {
            parseErrors.add(message);
        }
    }
}
