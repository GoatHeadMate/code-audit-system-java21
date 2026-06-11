package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.StorageAccess;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class StorageAccessClassifier {
    private static final Set<String> READ_PREFIXES = Set.of(
            "find", "get", "read", "load", "query",
            "select", "fetch", "poll", "scan"
    );
    private static final Set<String> WRITE_PREFIXES = Set.of(
            "save", "insert", "update", "write",
            "put", "set", "persist", "merge"
    );

    StorageAccess classify(
            String methodId,
            String filePath,
            int line,
            String method,
            String receiver,
            String receiverType,
            String expression,
            String firstArgument,
            Map<String, String> variableTypes
    ) {
        String storageKey = storageKey(receiver, receiverType);
        if (storageKey.isBlank()) {
            return null;
        }
        String kind = operationKind(method);
        if (kind == null) {
            return null;
        }
        return new StorageAccess(
                "storage-" + Integer.toUnsignedString(
                        (methodId + "|" + line + "|" + expression).hashCode()
                ),
                kind,
                storageKey,
                receiverType,
                method,
                methodId,
                filePath,
                line,
                expression,
                valueType(firstArgument, variableTypes)
        );
    }

    private String storageKey(String receiver, String receiverType) {
        String type = AnalysisTextUtils.simpleName(receiverType);
        if (!isStorageReceiver(type, receiver)) {
            return "";
        }
        if (!type.isBlank()) {
            return type;
        }
        String root = receiver.split("[.\\[(]", 2)[0];
        return root.isBlank() ? receiver : root;
    }

    private boolean isStorageReceiver(String type, String receiver) {
        String typeName = type.toLowerCase(Locale.ROOT);
        String receiverName = receiver.toLowerCase(Locale.ROOT);
        if (containsStrongStorageMarker(typeName)
                || containsStrongStorageMarker(receiverName)) {
            return true;
        }
        // Cache is too generic as a variable name. Require a static type.
        return typeName.contains("cache");
    }

    private boolean containsStrongStorageMarker(String value) {
        return value.contains("repository")
                || value.contains("mapper")
                || value.contains("dao")
                || value.contains("entitymanager")
                || value.contains("jdbctemplate")
                || value.contains("redistemplate")
                || value.contains("mongo")
                || value.contains("consumer");
    }

    private String operationKind(String method) {
        String lower = method.toLowerCase(Locale.ROOT);
        if (matchesPrefix(lower, WRITE_PREFIXES)) {
            return "WRITE";
        }
        if (matchesPrefix(lower, READ_PREFIXES)) {
            return "READ";
        }
        return null;
    }

    private boolean matchesPrefix(String value, Set<String> prefixes) {
        return prefixes.stream().anyMatch(value::startsWith);
    }

    private String valueType(
            String argument,
            Map<String, String> variableTypes
    ) {
        if (argument == null || argument.isBlank()) {
            return "";
        }
        String root = argument.split("[.\\[(]", 2)[0];
        return variableTypes.getOrDefault(root, "");
    }
}
