package com.huawei.audit.analysis.impl;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.resolution.TypeSolver;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

final class JavaSourceIndexer {
    private static final int MAX_PARSE_ERRORS = 1_000;
    private static final int MAX_PACKAGE_SCAN_LINES = 200;

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

        boolean symbolSolverEnabled = symbolSolverEnabled();
        ParserConfiguration configuration = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        if (symbolSolverEnabled) {
            configuration.setSymbolResolver(
                    new JavaSymbolSolver(buildTypeSolver(sourceRoot, sourceFiles))
            );
        }
        JavaParser parser = new JavaParser(configuration);

        List<MethodNode> methods = new ArrayList<>();
        List<Sink> sinks = new ArrayList<>();
        Map<String, Set<String>> implementations = new LinkedHashMap<>();
        List<String> parseErrors = new ArrayList<>();
        AtomicInteger methodSequence = new AtomicInteger();

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
                    extraRules,
                    symbolSolverEnabled
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
            List<DangerousSinkClassifier.ExtraSinkRule> extraRules,
            boolean symbolSolverEnabled
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
                        extraRules,
                        symbolSolverEnabled
                ),
                null
        );
    }

    private void recordError(List<String> parseErrors, String message) {
        if (parseErrors.size() < MAX_PARSE_ERRORS) {
            parseErrors.add(message);
        }
    }

    /**
     * Symbol resolution is opt-in: it is an order-of-magnitude slower and only
     * adds precision for project-internal types (no classpath = third-party
     * stays unresolved). Toggle via {@code -Daudit.symbol-solver=true} or the
     * {@code SYMBOL_SOLVER_ENABLED} environment variable. Default: off.
     */
    private boolean symbolSolverEnabled() {
        String property = System.getProperty("audit.symbol-solver");
        if (property != null) {
            return Boolean.parseBoolean(property);
        }
        return Boolean.parseBoolean(
                Optional.ofNullable(System.getenv("SYMBOL_SOLVER_ENABLED"))
                        .orElse("false")
        );
    }

    private TypeSolver buildTypeSolver(Path sourceRoot, List<Path> files) {
        CombinedTypeSolver combined = new CombinedTypeSolver();
        combined.add(new ReflectionTypeSolver());
        for (Path root : detectSourceRoots(sourceRoot, files)) {
            try {
                combined.add(new JavaParserTypeSolver(root));
            } catch (Exception ignored) {
                // A non-package-root directory is skipped; resolution falls back.
            }
        }
        return combined;
    }

    /**
     * Derives the source roots (package roots) for {@link JavaParserTypeSolver}
     * by subtracting each file's declared package from its directory, so any
     * layout (Maven, Gradle, flat) is handled without build-tool assumptions.
     */
    private Set<Path> detectSourceRoots(Path sourceRoot, List<Path> files) {
        Set<Path> roots = new LinkedHashSet<>();
        for (Path file : files) {
            Path directory = file.getParent();
            if (directory == null) {
                continue;
            }
            String declaredPackage = readPackage(file);
            if (declaredPackage.isEmpty()) {
                roots.add(directory);
                continue;
            }
            Path root = directory;
            int segments = declaredPackage.split("\\.").length;
            for (int index = 0; index < segments && root != null; index++) {
                root = root.getParent();
            }
            roots.add(root != null ? root : directory);
        }
        if (roots.isEmpty()) {
            roots.add(sourceRoot);
        }
        return roots;
    }

    private String readPackage(Path file) {
        try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
            return lines
                    .limit(MAX_PACKAGE_SCAN_LINES)
                    .map(String::strip)
                    .filter(line -> line.startsWith("package "))
                    .map(line -> line.substring("package ".length())
                            .replace(";", "")
                            .strip())
                    .findFirst()
                    .orElse("");
        } catch (Exception ignored) {
            return "";
        }
    }
}
