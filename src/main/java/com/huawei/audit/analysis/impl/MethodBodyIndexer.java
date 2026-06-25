package com.huawei.audit.analysis.impl;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.MethodReferenceExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Assignment;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageAccess;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

final class MethodBodyIndexer extends VoidVisitorAdapter<Void> {
    private final CompilationUnitIndexer source;
    private final String methodId;
    private final Map<String, String> variableTypes;
    private final List<Sink> sinks;
    private final List<CallSite> calls = new ArrayList<>();
    private final List<String> methodReferences = new ArrayList<>();
    private final List<StorageAccess> storageAccesses = new ArrayList<>();
    private final List<Assignment> assignments = new ArrayList<>();
    private final List<String> returnExpressions = new ArrayList<>();
    private final DangerousSinkClassifier sinkClassifier;
    private final StorageAccessClassifier storageClassifier =
            new StorageAccessClassifier();
    private final boolean symbolSolverEnabled;

    MethodBodyIndexer(
            CompilationUnitIndexer source,
            String methodId,
            Map<String, String> variableTypes,
            List<Sink> sinks,
            List<DangerousSinkClassifier.ExtraSinkRule> extraRules,
            boolean symbolSolverEnabled
    ) {
        this.source = source;
        this.methodId = methodId;
        this.variableTypes = variableTypes;
        this.sinks = sinks;
        this.sinkClassifier = new DangerousSinkClassifier(extraRules);
        this.symbolSolverEnabled = symbolSolverEnabled;
    }

    @Override
    public void visit(VariableDeclarator tree, Void unused) {
        variableTypes.put(
                tree.getNameAsString(),
                AnalysisTextUtils.simpleName(tree.getType().asString())
        );
        tree.getInitializer().ifPresent(init ->
                assignments.add(new Assignment(
                        tree.getNameAsString(),
                        source.sourceText(init, 300)
                )));
        super.visit(tree, unused);
    }

    @Override
    public void visit(AssignExpr tree, Void unused) {
        String target = tree.getTarget().toString().split("[.\\[(]", 2)[0];
        assignments.add(new Assignment(
                target,
                source.sourceText(tree.getValue(), 300)
        ));
        super.visit(tree, unused);
    }

    @Override
    public void visit(ForEachStmt tree, Void unused) {
        // A for-each binding `for (X v : iterable)` makes v derive from iterable:
        // model it as an assignment v = iterable so taint flows from a tainted
        // collection into the loop variable (e.g. iterating a tainted Map).
        var declarators = tree.getVariable().getVariables();
        if (!declarators.isEmpty()) {
            assignments.add(new Assignment(
                    declarators.get(0).getNameAsString(),
                    source.sourceText(tree.getIterable(), 200)
            ));
        }
        super.visit(tree, unused);
    }

    @Override
    public void visit(ReturnStmt tree, Void unused) {
        tree.getExpression().ifPresent(expr ->
                returnExpressions.add(source.sourceText(expr, 300)));
        super.visit(tree, unused);
    }

    @Override
    public void visit(MethodCallExpr tree, Void unused) {
        String methodName = tree.getNameAsString();
        String receiver = tree.getScope().map(Object::toString).orElse("");
        String receiverType = resolveScopeType(tree)
                .orElseGet(() -> receiverType(receiver));
        String expression = source.sourceText(tree, 500);
        calls.add(new CallSite(
                methodName,
                receiver,
                receiverType,
                tree.getArguments().size(),
                tree.getArguments().stream()
                        .map(this::expressionType)
                        .toList(),
                tree.getArguments().stream()
                        .map(argument -> source.sourceText(argument, 200))
                        .toList(),
                source.line(tree, true),
                expression
        ));
        String methodSelect = tree.getScope()
                .map(scope -> scope.toString() + "." + methodName)
                .orElse(methodName);
        DangerousSinkClassifier.SinkMatch sink = sinkClassifier.classify(
                methodName,
                methodSelect,
                receiverType
        );
        if (sink != null) {
            addSink(sink.category(), sink.api(), tree);
        }
        StorageAccess storage = storageClassifier.classify(
                methodId,
                source.filePath(),
                source.line(tree, true),
                methodName,
                receiver,
                receiverType,
                expression,
                tree.getArguments().isEmpty()
                        ? ""
                        : tree.getArgument(0).toString(),
                variableTypes
        );
        if (storage != null) {
            storageAccesses.add(storage);
        }
        super.visit(tree, unused);
    }

    @Override
    public void visit(ObjectCreationExpr tree, Void unused) {
        String type = AnalysisTextUtils.simpleName(tree.getType().asString());
        if ("ProcessBuilder".equals(type)) {
            addSink("COMMAND_EXECUTION", "new ProcessBuilder", tree);
        } else if ("XMLDecoder".equals(type)) {
            addSink("NATIVE_DESERIALIZATION", "new XMLDecoder", tree);
        } else if ("URLClassLoader".equals(type)) {
            addSink("DYNAMIC_LOADING", "new URLClassLoader", tree);
        } else if ("RedirectView".equals(type)) {
            addSink("HTTP_REDIRECT", "new RedirectView", tree);
        } else if (Set.of(
                "FileOutputStream",
                "FileWriter",
                "RandomAccessFile"
        ).contains(type)) {
            addSink("FILE_WRITE", "new " + type, tree);
        }
        if (!tree.getArguments().isEmpty()) {
            calls.add(new CallSite(
                    "<init>",
                    type,
                    type,
                    tree.getArguments().size(),
                    tree.getArguments().stream()
                            .map(this::expressionType)
                            .toList(),
                    tree.getArguments().stream()
                            .map(argument -> source.sourceText(argument, 200))
                            .toList(),
                    source.line(tree, true),
                    source.sourceText(tree, 500)
            ));
        }
        super.visit(tree, unused);
    }

    @Override
    public void visit(MethodReferenceExpr tree, Void unused) {
        methodReferences.add(tree.getIdentifier());
        super.visit(tree, unused);
    }

    List<CallSite> calls() {
        return calls;
    }

    Map<String, String> variableTypes() {
        return variableTypes;
    }

    List<String> methodReferences() {
        return methodReferences;
    }

    List<StorageAccess> storageAccesses() {
        return storageAccesses;
    }

    List<Assignment> assignments() {
        return assignments;
    }

    List<String> returnExpressions() {
        return returnExpressions;
    }

    private void addSink(String category, String api, Node node) {
        sinks.add(new Sink(
                "sink-" + (sinks.size() + 1),
                category,
                api,
                methodId,
                source.filePath(),
                source.line(node, true),
                source.sourceText(node, 500),
                sinkArguments(node)
        ));
    }

    /**
     * Source text of the arguments passed to a sink call/constructor, so the
     * candidate carries "what flows into the dangerous operation" (e.g. the
     * command string passed to {@code ProcessBuilder}/{@code exec}), not just
     * "this method contains a sink". Generic over any sink call — no project or
     * API specifics. Empty when the sink node carries no arguments.
     */
    private String sinkArguments(Node node) {
        NodeList<Expression> arguments = null;
        if (node instanceof MethodCallExpr call) {
            arguments = call.getArguments();
        } else if (node instanceof ObjectCreationExpr creation) {
            arguments = creation.getArguments();
        }
        if (arguments == null || arguments.isEmpty()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        for (Expression argument : arguments) {
            String text = source.sourceText(argument, 120);
            if (!text.isBlank()) {
                parts.add(text);
            }
        }
        return String.join(", ", parts);
    }

    private String receiverType(String receiver) {
        if (receiver == null || receiver.isBlank()) {
            return "";
        }
        String normalized = receiver.startsWith("this.")
                ? receiver.substring("this.".length())
                : receiver.startsWith("super.")
                ? receiver.substring("super.".length())
                : receiver;
        String root = normalized.split("[.\\[(]", 2)[0];
        String variableType = variableTypes.get(root);
        return variableType != null
                ? variableType
                : AnalysisTextUtils.startsUppercase(root) ? root : "";
    }

    private Optional<String> resolveScopeType(MethodCallExpr call) {
        if (!symbolSolverEnabled) {
            return Optional.empty();
        }
        return call.getScope().flatMap(scope -> {
            try {
                String resolved = AnalysisTextUtils.simpleName(
                        scope.calculateResolvedType().describe());
                return resolved.isBlank()
                        ? Optional.empty()
                        : Optional.of(resolved);
            } catch (Throwable ignored) {
                return Optional.empty();
            }
        });
    }

    private String expressionType(Expression expression) {
        if (symbolSolverEnabled) {
            try {
                String resolved = AnalysisTextUtils.simpleName(
                        expression.calculateResolvedType().describe());
                if (!resolved.isBlank()) {
                    return resolved;
                }
            } catch (Throwable ignored) {
                // Fall back to the lexical heuristic below.
            }
        }
        if (expression.isNameExpr()) {
            return variableTypes.getOrDefault(
                    expression.asNameExpr().getNameAsString(),
                    ""
            );
        }
        if (expression.isObjectCreationExpr()) {
            return AnalysisTextUtils.simpleName(
                    expression.asObjectCreationExpr().getType().asString()
            );
        }
        if (expression.isCastExpr()) {
            return AnalysisTextUtils.simpleName(
                    expression.asCastExpr().getType().asString()
            );
        }
        if (expression.isEnclosedExpr()) {
            return expressionType(expression.asEnclosedExpr().getInner());
        }
        return "";
    }
}
