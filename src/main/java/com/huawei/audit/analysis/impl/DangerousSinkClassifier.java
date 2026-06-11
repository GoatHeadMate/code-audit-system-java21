package com.huawei.audit.analysis.impl;

import java.util.Locale;
import java.util.Set;

final class DangerousSinkClassifier {
    SinkMatch classify(
            String method,
            String expression,
            String receiverType
    ) {
        String lowerExpression = expression.toLowerCase(Locale.ROOT);
        String lowerType = receiverType.toLowerCase(Locale.ROOT);

        if ("exec".equals(method) && expression.contains("Runtime")) {
            return match("COMMAND_EXECUTION", expression);
        }
        if ("start".equals(method)
                && (expression.contains("ProcessBuilder")
                || "ProcessBuilder".equals(receiverType))) {
            return match("COMMAND_EXECUTION", expression);
        }
        if (isExpressionExecution(method, lowerExpression, lowerType)) {
            return match("SCRIPT_OR_EXPRESSION_EXECUTION", expression);
        }
        if (isDeserialization(method, lowerExpression, lowerType)) {
            return match("NATIVE_DESERIALIZATION", expression);
        }
        if (isDynamicLoading(method, lowerExpression, lowerType)) {
            return match("DYNAMIC_LOADING", expression);
        }
        if ("lookup".equals(method)
                && (lowerExpression.contains("context")
                || lowerExpression.contains("jndi"))) {
            return match("JNDI_LOOKUP", expression);
        }
        if (Set.of("write", "writeString", "copy", "move").contains(method)
                && expression.startsWith("Files.")) {
            return match("FILE_WRITE", expression);
        }
        if ("transferTo".equals(method)) {
            return match("FILE_WRITE", expression);
        }
        if ("openConnection".equals(method)
                || Set.of("send", "sendAsync", "exchange").contains(method)
                && (lowerExpression.contains("http")
                || lowerExpression.contains("resttemplate"))) {
            return match("OUTBOUND_HTTP", expression);
        }
        if (Set.of("load", "loadLibrary").contains(method)
                && expression.startsWith("System.")) {
            return match("NATIVE_LIBRARY", expression);
        }
        return null;
    }

    private boolean isExpressionExecution(
            String method,
            String expression,
            String receiverType
    ) {
        if (Set.of("eval", "executeExpression", "parseExpression")
                .contains(method)) {
            return true;
        }
        if ("execute".equals(method)
                && (expression.contains("mvel")
                || expression.contains("compiled")
                || receiverType.contains("mvel"))) {
            return true;
        }
        if (Set.of("evaluate", "run", "parseClass").contains(method)
                && containsAny(
                        expression + " " + receiverType,
                        "groovy", "velocity", "ognl", "elprocessor"
                )) {
            return true;
        }
        if ("process".equals(method)
                && containsAny(
                        expression + " " + receiverType,
                        "template", "freemarker"
                )) {
            return true;
        }
        if (Set.of("getValue", "setValue", "createValueExpression")
                .contains(method)
                && containsAny(
                        expression + " " + receiverType,
                        "expression", "ognl", "elprocessor", "spel"
                )) {
            return true;
        }
        return false;
    }

    private boolean isDeserialization(
            String method,
            String expression,
            String receiverType
    ) {
        if (Set.of(
                "readObject",
                "fromXML",
                "enableDefaultTyping",
                "activateDefaultTyping"
        ).contains(method)) {
            return true;
        }
        if (Set.of("load", "loadAll").contains(method)
                && containsAny(
                        expression + " " + receiverType,
                        "yaml", "snakeyaml"
                )) {
            return true;
        }
        return Set.of("parse", "parseObject").contains(method)
                && containsAny(
                        expression + " " + receiverType,
                        "json", "fastjson"
                );
    }

    private boolean isDynamicLoading(
            String method,
            String expression,
            String receiverType
    ) {
        if (Set.of("forName", "loadClass", "defineClass").contains(method)) {
            return true;
        }
        return Set.of("invoke", "newInstance").contains(method)
                && containsAny(
                        expression + " " + receiverType,
                        "method", "constructor", "class"
                );
    }

    private boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private SinkMatch match(String category, String api) {
        return new SinkMatch(category, api);
    }

    record SinkMatch(String category, String api) { }
}
