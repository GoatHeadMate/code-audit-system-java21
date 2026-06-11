package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePathScanner;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

final class CompilationUnitIndexer extends TreePathScanner<Void, Void> {
    private final CompilationUnitTree unit;
    private final SourcePositions positions;
    private final String filePath;
    private final String source;
    private final List<MethodNode> methods;
    private final List<Sink> sinks;
    private final Map<String, Set<String>> implementations;
    private final AtomicInteger methodSequence;
    private final Deque<ClassContext> classes = new ArrayDeque<>();

    CompilationUnitIndexer(
            CompilationUnitTree unit,
            SourcePositions positions,
            String filePath,
            String source,
            List<MethodNode> methods,
            List<Sink> sinks,
            Map<String, Set<String>> implementations,
            AtomicInteger methodSequence
    ) {
        this.unit = unit;
        this.positions = positions;
        this.filePath = filePath;
        this.source = source;
        this.methods = methods;
        this.sinks = sinks;
        this.implementations = implementations;
        this.methodSequence = methodSequence;
    }

    @Override
    public Void visitClass(ClassTree tree, Void unused) {
        String className = tree.getSimpleName().toString();
        Map<String, String> fieldTypes = new LinkedHashMap<>();
        for (Tree member : tree.getMembers()) {
            if (member instanceof VariableTree variable) {
                fieldTypes.put(
                        variable.getName().toString(),
                        AnalysisTextUtils.simpleName(variable.getType().toString())
                );
            }
        }
        for (Tree implemented : tree.getImplementsClause()) {
            registerImplementation(implemented.toString(), className);
        }
        if (tree.getExtendsClause() != null) {
            registerImplementation(tree.getExtendsClause().toString(), className);
        }
        classes.push(new ClassContext(className, Map.copyOf(fieldTypes)));
        super.visitClass(tree, unused);
        classes.pop();
        return null;
    }

    @Override
    public Void visitMethod(MethodTree tree, Void unused) {
        if (classes.isEmpty() || tree.getBody() == null) {
            return null;
        }
        ClassContext owner = classes.peek();
        int startLine = line(tree, true);
        String methodName = tree.getName().toString();
        String methodId = owner.className() + "#" + methodName + "/"
                + tree.getParameters().size() + "@"
                + filePath + ":" + startLine + ":"
                + methodSequence.incrementAndGet();
        Map<String, String> variableTypes = new LinkedHashMap<>(
                owner.fieldTypes()
        );
        for (VariableTree parameter : tree.getParameters()) {
            variableTypes.put(
                    parameter.getName().toString(),
                    AnalysisTextUtils.simpleName(parameter.getType().toString())
            );
        }

        MethodBodyIndexer body = new MethodBodyIndexer(
                this,
                methodId,
                variableTypes,
                sinks
        );
        body.scan(tree.getBody(), null);
        methods.add(new MethodNode(
                methodId,
                owner.className(),
                methodName,
                tree.getParameters().size(),
                filePath,
                startLine,
                line(tree, false),
                sourceText(tree, 400),
                List.copyOf(body.calls()),
                Map.copyOf(body.variableTypes()),
                List.copyOf(body.storageAccesses())
        ));
        return null;
    }

    int line(Tree tree, boolean start) {
        long position = start
                ? positions.getStartPosition(unit, tree)
                : positions.getEndPosition(unit, tree);
        return position < 0
                ? 0
                : (int) unit.getLineMap().getLineNumber(position);
    }

    String sourceText(Tree tree, int maxLength) {
        long start = positions.getStartPosition(unit, tree);
        long end = positions.getEndPosition(unit, tree);
        if (start < 0 || end < start || start >= source.length()) {
            return tree.toString().replaceAll("\\s+", " ").strip();
        }
        int boundedEnd = (int) Math.min(end, source.length());
        String text = source.substring((int) start, boundedEnd)
                .replaceAll("\\s+", " ")
                .strip();
        return text.length() > maxLength
                ? text.substring(0, maxLength)
                : text;
    }

    String filePath() {
        return filePath;
    }

    private void registerImplementation(String parent, String child) {
        implementations.computeIfAbsent(
                AnalysisTextUtils.simpleName(parent),
                ignored -> new LinkedHashSet<>()
        ).add(child);
    }

    private record ClassContext(
            String className,
            Map<String, String> fieldTypes
    ) { }
}
