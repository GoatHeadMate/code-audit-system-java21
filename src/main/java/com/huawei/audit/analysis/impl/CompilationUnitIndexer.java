package com.huawei.audit.analysis.impl;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

final class CompilationUnitIndexer extends VoidVisitorAdapter<Void> {
    private final String filePath;
    private final List<MethodNode> methods;
    private final List<Sink> sinks;
    private final Map<String, Set<String>> implementations;
    private final AtomicInteger methodSequence;
    private final List<DangerousSinkClassifier.ExtraSinkRule> extraRules;
    private final boolean symbolSolverEnabled;
    private final Deque<ClassContext> classes = new ArrayDeque<>();

    CompilationUnitIndexer(
            String filePath,
            List<MethodNode> methods,
            List<Sink> sinks,
            Map<String, Set<String>> implementations,
            AtomicInteger methodSequence,
            List<DangerousSinkClassifier.ExtraSinkRule> extraRules,
            boolean symbolSolverEnabled
    ) {
        this.filePath = filePath;
        this.methods = methods;
        this.sinks = sinks;
        this.implementations = implementations;
        this.methodSequence = methodSequence;
        this.extraRules = extraRules;
        this.symbolSolverEnabled = symbolSolverEnabled;
    }

    @Override
    public void visit(ClassOrInterfaceDeclaration tree, Void unused) {
        NodeList<ClassOrInterfaceType> extended = tree.getExtendedTypes();
        NodeList<ClassOrInterfaceType> implemented = tree.getImplementedTypes();
        // javac models interface super-interfaces as the "implements" clause.
        Set<String> implInterfaces = new LinkedHashSet<>();
        (tree.isInterface() ? extended : implemented).forEach(type ->
                implInterfaces.add(AnalysisTextUtils.simpleName(type.toString())));
        String extendsClass = !tree.isInterface() && !extended.isEmpty()
                ? AnalysisTextUtils.simpleName(extended.get(0).toString())
                : "";
        extended.forEach(type ->
                registerImplementation(type.toString(), tree.getNameAsString()));
        implemented.forEach(type ->
                registerImplementation(type.toString(), tree.getNameAsString()));
        pushContext(tree, extendsClass, implInterfaces);
        super.visit(tree, unused);
        classes.pop();
    }

    @Override
    public void visit(EnumDeclaration tree, Void unused) {
        enterImplementingType(tree, tree.getImplementedTypes());
        super.visit(tree, unused);
        classes.pop();
    }

    @Override
    public void visit(RecordDeclaration tree, Void unused) {
        enterImplementingType(tree, tree.getImplementedTypes());
        super.visit(tree, unused);
        classes.pop();
    }

    private void enterImplementingType(
            TypeDeclaration<?> tree,
            NodeList<ClassOrInterfaceType> implemented
    ) {
        Set<String> implInterfaces = new LinkedHashSet<>();
        implemented.forEach(type -> {
            implInterfaces.add(AnalysisTextUtils.simpleName(type.toString()));
            registerImplementation(type.toString(), tree.getNameAsString());
        });
        pushContext(tree, "", implInterfaces);
    }

    private void pushContext(
            TypeDeclaration<?> tree,
            String extendsClass,
            Set<String> implInterfaces
    ) {
        Map<String, String> fieldTypes = new LinkedHashMap<>();
        for (FieldDeclaration field : tree.getFields()) {
            for (VariableDeclarator variable : field.getVariables()) {
                fieldTypes.put(
                        variable.getNameAsString(),
                        AnalysisTextUtils.simpleName(variable.getType().asString())
                );
            }
        }
        classes.push(new ClassContext(
                tree.getNameAsString(),
                Map.copyOf(fieldTypes),
                hasAnnotation(
                        tree.getAnnotations(),
                        "Endpoint",
                        "WebEndpoint",
                        "ControllerEndpoint",
                        "RestControllerEndpoint"
                ),
                extendsClass,
                Set.copyOf(implInterfaces)
        ));
    }

    @Override
    public void visit(MethodDeclaration tree, Void unused) {
        if (classes.isEmpty() || tree.getBody().isEmpty()) {
            return;
        }
        ClassContext owner = classes.peek();
        int startLine = line(tree, true);
        String methodName = tree.getNameAsString();
        String methodId = owner.className() + "#" + methodName + "/"
                + tree.getParameters().size() + "@"
                + filePath + ":" + startLine + ":"
                + methodSequence.incrementAndGet();
        Map<String, String> variableTypes = new LinkedHashMap<>(
                owner.fieldTypes()
        );
        for (Parameter parameter : tree.getParameters()) {
            variableTypes.put(
                    parameter.getNameAsString(),
                    AnalysisTextUtils.simpleName(parameter.getType().asString())
            );
        }
        List<String> parameterNames = tree.getParameters().stream()
                .map(Parameter::getNameAsString)
                .toList();

        MethodBodyIndexer body = new MethodBodyIndexer(
                this,
                methodId,
                variableTypes,
                sinks,
                extraRules,
                symbolSolverEnabled
        );
        if (owner.actuatorEndpoint() && hasAnnotation(
                tree.getAnnotations(),
                "ReadOperation",
                "WriteOperation",
                "DeleteOperation"
        )) {
            sinks.add(new Sink(
                    "sink-" + (sinks.size() + 1),
                    "ACTUATOR_ENDPOINT",
                    "Spring Actuator operation",
                    methodId,
                    filePath,
                    startLine,
                    sourceText(tree, 500)
            ));
        }
        if ("HttpServlet".equals(owner.extendsClass())
                && Set.of("doGet", "doPost", "doPut", "doDelete", "service")
                        .contains(methodName)) {
            sinks.add(new Sink(
                    "sink-" + (sinks.size() + 1),
                    "SERVLET_ENTRY",
                    "HttpServlet." + methodName,
                    methodId,
                    filePath,
                    startLine,
                    sourceText(tree, 500)
            ));
        }
        if (owner.implementsInterfaces().contains("Filter")
                && "doFilter".equals(methodName)) {
            sinks.add(new Sink(
                    "sink-" + (sinks.size() + 1),
                    "FILTER_ENTRY",
                    "Filter.doFilter",
                    methodId,
                    filePath,
                    startLine,
                    sourceText(tree, 500)
            ));
        }
        tree.getBody().ifPresent(block -> block.accept(body, null));
        methods.add(new MethodNode(
                methodId,
                owner.className(),
                methodName,
                tree.getParameters().size(),
                List.copyOf(parameterNames),
                filePath,
                startLine,
                line(tree, false),
                sourceText(tree, 400),
                List.copyOf(body.calls()),
                Map.copyOf(body.variableTypes()),
                List.copyOf(body.methodReferences()),
                List.copyOf(body.storageAccesses()),
                List.copyOf(body.assignments()),
                List.copyOf(body.returnExpressions())
        ));
    }

    int line(Node node, boolean start) {
        return node.getRange()
                .map(range -> start ? range.begin.line : range.end.line)
                .orElse(0);
    }

    String sourceText(Node node, int maxLength) {
        String text = node.getTokenRange()
                .map(Object::toString)
                .orElseGet(node::toString)
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

    private boolean hasAnnotation(
            List<? extends AnnotationExpr> annotations,
            String... names
    ) {
        Set<String> accepted = Set.of(names);
        return annotations.stream()
                .map(annotation -> AnalysisTextUtils.simpleName(
                        annotation.getNameAsString()
                ))
                .anyMatch(accepted::contains);
    }

    private record ClassContext(
            String className,
            Map<String, String> fieldTypes,
            boolean actuatorEndpoint,
            String extendsClass,
            Set<String> implementsInterfaces
    ) { }
}
