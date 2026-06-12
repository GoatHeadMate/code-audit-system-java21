package com.huawei.audit.analysis.impl;

import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class MethodTaintAnalyzer {
    private static final Set<String> SINK_CATEGORIES = Set.of(
            "COMMAND_EXECUTION", "SCRIPT_OR_EXPRESSION_EXECUTION"
    );
    private static final Pattern PARAM_NAMES_PATTERN = Pattern.compile(
            "\\b([a-z][a-zA-Z0-9_]*)\\b"
    );
    private static final Set<String> JAVA_KEYWORDS = Set.of(
            "abstract", "assert", "boolean", "break", "byte", "case", "catch",
            "char", "class", "const", "continue", "default", "do", "double",
            "else", "enum", "extends", "final", "finally", "float", "for",
            "goto", "if", "implements", "import", "instanceof", "int",
            "interface", "long", "native", "new", "null", "package", "private",
            "protected", "public", "return", "short", "static", "strictfp",
            "super", "switch", "synchronized", "this", "throw", "throws",
            "transient", "try", "void", "volatile", "while", "var", "true",
            "false", "string", "list", "map", "set", "object", "optional"
    );

    List<Sink> findTaintSinks(
            List<MethodNode> methods,
            List<Sink> existingSinks
    ) {
        Map<String, List<Sink>> cmdSinksByMethod = new LinkedHashMap<>();
        for (Sink sink : existingSinks) {
            if (SINK_CATEGORIES.contains(sink.category())) {
                cmdSinksByMethod
                        .computeIfAbsent(sink.methodId(), ignored -> new ArrayList<>())
                        .add(sink);
            }
        }

        List<Sink> result = new ArrayList<>();
        int seq = 0;
        for (MethodNode method : methods) {
            List<Sink> sinks = cmdSinksByMethod.get(method.id());
            if (sinks == null || sinks.isEmpty()) {
                continue;
            }
            if (method.signature() == null || method.signature().isBlank()) {
                continue;
            }
            if (hasDirectTaintEvidence(sinks)) {
                continue;
            }
            Set<String> params = extractParamNames(method.signature());
            if (params.isEmpty()) {
                continue;
            }
            if (paramDirectlyInSinkCode(method, sinks, params)) {
                continue;
            }
            if (hasParamToSinkFlow(method, sinks, params)) {
                result.add(new Sink(
                        "taint-" + (++seq),
                        sinks.getFirst().category(),
                        "taint:" + method.className() + "." + method.methodName(),
                        method.id(),
                        method.filePath(),
                        method.startLine(),
                        method.signature()
                ));
            }
        }
        return result;
    }

    private boolean hasDirectTaintEvidence(List<Sink> sinks) {
        for (Sink sink : sinks) {
            String code = sink.code();
            if (code == null) continue;
            String lower = code.toLowerCase(java.util.Locale.ROOT);
            if ((lower.contains("replace") || lower.contains("format")
                    || lower.contains("concat") || lower.contains("+"))
                    && (lower.contains("exec") || lower.contains("processbuilder")
                    || lower.contains("start()"))) {
                return true;
            }
        }
        return false;
    }

    private boolean paramDirectlyInSinkCode(
            MethodNode method, List<Sink> sinks, Set<String> params
    ) {
        for (CallSite call : method.calls()) {
            if (isStringOperation(call.methodName())) {
                return false;
            }
        }
        for (Sink sink : sinks) {
            String code = sink.code();
            if (code != null && containsParamReference(code, params)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasParamToSinkFlow(
            MethodNode method,
            List<Sink> sinks,
            Set<String> params
    ) {
        List<CallSite> calls = method.calls();
        if (calls.isEmpty()) {
            return false;
        }
        for (CallSite call : calls) {
            String expr = call.expression();
            if (expr == null || expr.isBlank()) {
                continue;
            }
            if (!isStringOperation(call.methodName())) {
                continue;
            }
            if (containsParamReference(expr, params) && reachesSink(calls, call)) {
                return true;
            }
        }
        for (CallSite call : calls) {
            if (!isSinkCall(call)) {
                continue;
            }
            String expr = call.expression();
            if (expr != null && containsParamReference(expr, params)) {
                return true;
            }
        }
        return false;
    }

    private boolean isStringOperation(String method) {
        return Set.of(
                "format", "replace", "replaceAll", "replaceFirst",
                "concat", "append", "toString", "valueOf",
                "substring", "trim", "strip", "toLowerCase", "toUpperCase"
        ).contains(method);
    }

    private boolean containsParamReference(String expr, Set<String> params) {
        for (String param : params) {
            if (expr.contains(param)) {
                return true;
            }
        }
        return false;
    }

    private boolean reachesSink(List<CallSite> calls, CallSite source) {
        int sourceIndex = calls.indexOf(source);
        if (sourceIndex < 0) {
            return false;
        }
        for (int i = sourceIndex + 1; i < calls.size(); i++) {
            CallSite subsequent = calls.get(i);
            if (isSinkMethod(subsequent.methodName())) {
                return true;
            }
        }
        return false;
    }

    private boolean isSinkMethod(String method) {
        return Set.of("exec", "start", "run", "evaluate").contains(method);
    }

    private boolean isSinkCall(CallSite call) {
        if (isSinkMethod(call.methodName())) {
            return true;
        }
        String expr = call.expression() != null ? call.expression() : "";
        return expr.contains("ProcessBuilder") || expr.contains("Runtime");
    }

    private Set<String> extractParamNames(String signature) {
        Set<String> names = new LinkedHashSet<>();
        if (signature == null || signature.isBlank()) {
            return names;
        }
        int parenStart = signature.indexOf('(');
        int parenEnd = signature.lastIndexOf(')');
        String paramsSection = parenStart >= 0 && parenEnd > parenStart
                ? signature.substring(parenStart + 1, parenEnd)
                : signature;
        String[] parts = paramsSection.split(",");
        for (String part : parts) {
            String trimmed = part.strip();
            String[] tokens = trimmed.split("\\s+");
            if (tokens.length >= 2) {
                String name = tokens[tokens.length - 1];
                if (!name.isEmpty() && Character.isLowerCase(name.charAt(0))
                        && !JAVA_KEYWORDS.contains(name.toLowerCase())) {
                    names.add(name);
                }
            }
        }
        if (names.isEmpty()) {
            Matcher matcher = PARAM_NAMES_PATTERN.matcher(signature);
            while (matcher.find()) {
                String name = matcher.group(1);
                if (!JAVA_KEYWORDS.contains(name.toLowerCase())) {
                    names.add(name);
                }
            }
        }
        return names;
    }
}
