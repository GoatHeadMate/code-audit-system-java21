package com.huawei.audit.analysis.impl;

import java.util.List;
import java.util.Locale;
import java.util.Set;

final class DangerousSinkClassifier {
    private final List<ExtraSinkRule> extraRules;

    DangerousSinkClassifier() {
        this.extraRules = List.of();
    }

    DangerousSinkClassifier(List<ExtraSinkRule> extraRules) {
        this.extraRules = extraRules == null ? List.of() : List.copyOf(extraRules);
    }

    SinkMatch classify(
            String method,
            String expression,
            String receiverType
    ) {
        String lowerExpression = expression.toLowerCase(Locale.ROOT);
        String lowerType = receiverType.toLowerCase(Locale.ROOT);

        if (method.startsWith("exec") && expression.contains("Runtime")) {
            return match("COMMAND_EXECUTION", expression);
        }
        if ("start".equals(method)
                && (expression.contains("ProcessBuilder")
                || "ProcessBuilder".equals(receiverType))) {
            return match("COMMAND_EXECUTION", expression);
        }
        if (isReplaceCommandExecution(method, lowerExpression)) {
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
        if (isSqlExecution(method, lowerExpression, lowerType)) {
            return match("SQL_EXECUTION", expression);
        }
        if (isXmlParsing(method, lowerExpression, lowerType)) {
            return match("XML_PARSE", expression);
        }
        if (isResponseWrite(method, lowerExpression, lowerType)) {
            return match("HTTP_RESPONSE_WRITE", expression);
        }
        if (isHeaderWrite(method, lowerExpression, lowerType)) {
            return match("HTTP_HEADER_WRITE", expression);
        }
        if ("sendRedirect".equals(method)) {
            return match("HTTP_REDIRECT", expression);
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
        if (("openConnection".equals(method)
                || Set.of("send", "sendAsync", "exchange").contains(method))
                && (lowerExpression.contains("http")
                || lowerExpression.contains("resttemplate"))) {
            return match("OUTBOUND_HTTP", expression);
        }
        if (Set.of("load", "loadLibrary").contains(method)
                && expression.startsWith("System.")) {
            return match("NATIVE_LIBRARY", expression);
        }
        for (ExtraSinkRule rule : extraRules) {
            if (rule.methodNamePattern().equals(method)
                    && lowerType.contains(rule.receiverTypePattern())) {
                return match(rule.category(), expression);
            }
        }
        return null;
    }

    private boolean isSqlExecution(
            String method,
            String expression,
            String receiverType
    ) {
        String target = expression + " " + receiverType;
        if (Set.of(
                "createQuery",
                "createNativeQuery",
                "createSQLQuery"
        ).contains(method)) {
            return containsAny(target, "entitymanager", "session");
        }
        if (Set.of(
                "execute",
                "executeQuery",
                "executeUpdate",
                "addBatch"
        ).contains(method)) {
            return containsAny(
                    target,
                    "statement", "preparedstatement", "query"
            );
        }
        return Set.of(
                "batchUpdate",
                "query",
                "queryForList",
                "queryForMap",
                "queryForObject",
                "update"
        ).contains(method) && containsAny(
                target,
                "jdbctemplate", "namedparameterjdbctemplate"
        );
    }

    private boolean isXmlParsing(
            String method,
            String expression,
            String receiverType
    ) {
        if (!Set.of("parse", "parseText", "read").contains(method)) {
            return false;
        }
        return containsAny(
                expression + " " + receiverType,
                "documentbuilder", "saxparser", "xmlreader",
                "saxbuilder", "saxreader", "dom4j", "xmlinputfactory"
        );
    }

    private boolean isResponseWrite(
            String method,
            String expression,
            String receiverType
    ) {
        if (!Set.of("append", "print", "println", "write").contains(method)) {
            return false;
        }
        return containsAny(
                expression + " " + receiverType,
                "getwriter", "printwriter", "servletoutputstream"
        );
    }

    private boolean isHeaderWrite(
            String method,
            String expression,
            String receiverType
    ) {
        if (!Set.of("addHeader", "setHeader").contains(method)) {
            return false;
        }
        return containsAny(
                expression + " " + receiverType,
                "httpservletresponse", "containerresponsecontext",
                "response", "resp", "rsp"
        );
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

    private boolean isReplaceCommandExecution(String method, String lowerExpression) {
        if (!Set.of("replace", "replaceAll").contains(method)) {
            return false;
        }
        return containsAny(lowerExpression, "bash", "sh ", "cmd", "exec",
                "processbuilder", "/bin/", "powershell", "python", "script", "shell");
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

    record ExtraSinkRule(
            String methodNamePattern,
            String receiverTypePattern,
            String category
    ) { }
}
