package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageAccess;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.TreeScanner;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class MethodBodyIndexer extends TreeScanner<Void, Void> {
    private final CompilationUnitIndexer source;
    private final String methodId;
    private final Map<String, String> variableTypes;
    private final List<Sink> sinks;
    private final List<CallSite> calls = new ArrayList<>();
    private final List<StorageAccess> storageAccesses = new ArrayList<>();
    private final DangerousSinkClassifier sinkClassifier =
            new DangerousSinkClassifier();
    private final StorageAccessClassifier storageClassifier =
            new StorageAccessClassifier();

    MethodBodyIndexer(
            CompilationUnitIndexer source,
            String methodId,
            Map<String, String> variableTypes,
            List<Sink> sinks
    ) {
        this.source = source;
        this.methodId = methodId;
        this.variableTypes = variableTypes;
        this.sinks = sinks;
    }

    @Override
    public Void visitVariable(VariableTree tree, Void unused) {
        if (tree.getType() != null) {
            variableTypes.put(
                    tree.getName().toString(),
                    AnalysisTextUtils.simpleName(tree.getType().toString())
            );
        }
        return super.visitVariable(tree, unused);
    }

    @Override
    public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
        Invocation invocation = invocation(tree);
        String receiverType = receiverType(invocation.receiver());
        String expression = source.sourceText(tree, 500);
        calls.add(new CallSite(
                invocation.methodName(),
                invocation.receiver(),
                receiverType,
                tree.getArguments().size(),
                source.line(tree, true),
                expression
        ));
        DangerousSinkClassifier.SinkMatch sink = sinkClassifier.classify(
                invocation.methodName(),
                tree.getMethodSelect().toString(),
                receiverType
        );
        if (sink != null) {
            addSink(sink.category(), sink.api(), tree);
        }
        StorageAccess storage = storageClassifier.classify(
                methodId,
                source.filePath(),
                source.line(tree, true),
                invocation.methodName(),
                invocation.receiver(),
                receiverType,
                expression,
                tree.getArguments().isEmpty()
                        ? ""
                        : tree.getArguments().getFirst().toString(),
                variableTypes
        );
        if (storage != null) {
            storageAccesses.add(storage);
        }
        return super.visitMethodInvocation(tree, unused);
    }

    @Override
    public Void visitNewClass(NewClassTree tree, Void unused) {
        String type = AnalysisTextUtils.simpleName(tree.getIdentifier().toString());
        if ("ProcessBuilder".equals(type)) {
            addSink("COMMAND_EXECUTION", "new ProcessBuilder", tree);
        } else if ("XMLDecoder".equals(type)) {
            addSink("NATIVE_DESERIALIZATION", "new XMLDecoder", tree);
        } else if ("URLClassLoader".equals(type)) {
            addSink("DYNAMIC_LOADING", "new URLClassLoader", tree);
        } else if (Set.of(
                "FileOutputStream",
                "FileWriter",
                "RandomAccessFile"
        ).contains(type)) {
            addSink("FILE_WRITE", "new " + type, tree);
        }
        return super.visitNewClass(tree, unused);
    }

    List<CallSite> calls() {
        return calls;
    }

    Map<String, String> variableTypes() {
        return variableTypes;
    }

    List<StorageAccess> storageAccesses() {
        return storageAccesses;
    }

    private void addSink(String category, String api, com.sun.source.tree.Tree tree) {
        sinks.add(new Sink(
                "sink-" + (sinks.size() + 1),
                category,
                api,
                methodId,
                source.filePath(),
                source.line(tree, true),
                source.sourceText(tree, 500)
        ));
    }

    private Invocation invocation(MethodInvocationTree tree) {
        ExpressionTree select = tree.getMethodSelect();
        if (select instanceof MemberSelectTree member) {
            return new Invocation(
                    member.getIdentifier().toString(),
                    member.getExpression().toString()
            );
        }
        if (select instanceof IdentifierTree identifier) {
            return new Invocation(identifier.getName().toString(), "");
        }
        return new Invocation(select.toString(), "");
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

    private record Invocation(String methodName, String receiver) { }
}
