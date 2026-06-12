package com.huawei.audit.analysis.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.CallSite;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.MethodNode;
import com.huawei.audit.analysis.WhiteBoxAnalysisService.Sink;
import com.huawei.audit.process.ProcessRunner;
import com.huawei.audit.process.ProcessResult;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

final class SuspiciousCallReviewer {
    private static final Set<String> SUSPICIOUS_METHODS = Set.of(
            "exec", "execute", "run", "eval", "invoke", "parse", "load",
            "send", "query", "process", "call", "dispatch", "resolve",
            "lookup", "deserialize", "unmarshal", "decode"
    );
    private static final int MAX_SUSPICIOUS = 200;
    private static final List<String> KNOWN_CATEGORIES = List.of(
            "COMMAND_EXECUTION", "SCRIPT_OR_EXPRESSION_EXECUTION",
            "NATIVE_DESERIALIZATION", "DYNAMIC_LOADING", "SQL_EXECUTION",
            "XML_PARSE", "HTTP_RESPONSE_WRITE", "HTTP_HEADER_WRITE",
            "HTTP_REDIRECT", "JNDI_LOOKUP", "FILE_WRITE",
            "OUTBOUND_HTTP", "NATIVE_LIBRARY"
    );
    private static final Pattern FENCED_JSON = Pattern.compile(
            "```(?:json)?\\s*([\\s\\S]*?)\\s*```",
            Pattern.CASE_INSENSITIVE
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    List<Sink> review(
            SourceIndex sourceIndex,
            ProcessRunner processRunner,
            String claudeBin,
            Path workingDirectory
    ) {
        try {
            if (processRunner == null || claudeBin == null) {
                return List.of();
            }
            Set<String> existingSinkKeys = sourceIndex.sinks().stream()
                    .map(s -> s.methodId() + "|" + s.line())
                    .collect(Collectors.toCollection(LinkedHashSet::new));

            Map<String, Set<String>> sourceMethods = sourceIndex.methodsByClassAndName()
                    .keySet().stream()
                    .collect(Collectors.groupingBy(
                            k -> k.split("#", 2)[0],
                            LinkedHashMap::new,
                            Collectors.toSet()
                    ));

            List<SuspiciousCall> suspicious = new ArrayList<>();
            Set<String> seenKeys = new LinkedHashSet<>();
            for (MethodNode method : sourceIndex.methods()) {
                for (CallSite call : method.calls()) {
                    String methodLower = call.methodName().toLowerCase(Locale.ROOT);
                    if (!SUSPICIOUS_METHODS.contains(methodLower)) {
                        continue;
                    }
                    String sinkKey = method.id() + "|" + call.line();
                    if (existingSinkKeys.contains(sinkKey)) {
                        continue;
                    }
                    String receiverType = call.receiverType();
                    if (receiverType.isEmpty()) {
                        continue;
                    }
                    if (sourceMethods.containsKey(receiverType)) {
                        continue;
                    }
                    String dedupKey = receiverType + "#" + call.methodName();
                    if (!seenKeys.add(dedupKey)) {
                        continue;
                    }
                    suspicious.add(new SuspiciousCall(
                            call.methodName(),
                            receiverType.toLowerCase(Locale.ROOT),
                            call.expression(),
                            method.id(),
                            method.filePath(),
                            call.line()
                    ));
                    if (suspicious.size() >= MAX_SUSPICIOUS) {
                        break;
                    }
                }
                if (suspicious.size() >= MAX_SUSPICIOUS) {
                    break;
                }
            }
            if (suspicious.isEmpty()) {
                return List.of();
            }
            String callList = suspicious.stream()
                    .map(sc -> sc.receiverType + "." + sc.methodName
                            + " — " + sc.expression)
                    .collect(Collectors.joining("\n"));
            String categories = String.join(", ", KNOWN_CATEGORIES);
            String prompt = PROMPT_TEMPLATE.formatted(callList, categories);
            List<String> command = List.of(
                    claudeBin, "--print", "--output-format", "json", "-p", prompt
            );
            ProcessResult result = processRunner.run(
                    command, workingDirectory, Map.of(),
                    Duration.ofSeconds(60), null, line -> {}
            );
            if (result.exitCode() != 0) {
                return List.of();
            }
            return parseAndConvert(
                    String.join("\n", result.output()), suspicious
            );
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private List<Sink> parseAndConvert(
            String rawOutput,
            List<SuspiciousCall> suspicious
    ) {
        try {
            String jsonArray = extractJsonArray(rawOutput);
            if (jsonArray == null) {
                return List.of();
            }
            List<Map<String, String>> items = objectMapper.readValue(
                    jsonArray, new TypeReference<>() {}
            );
            List<Sink> sinks = new ArrayList<>();
            int seq = 1;
            for (Map<String, String> item : items) {
                String methodName = item.getOrDefault("methodName", "").strip();
                String receiverType = item.getOrDefault("receiverType", "").strip()
                        .toLowerCase(Locale.ROOT);
                String category = item.getOrDefault("category", "").strip();
                if (methodName.isEmpty() || receiverType.isEmpty()
                        || !KNOWN_CATEGORIES.contains(category)) {
                    continue;
                }
                for (SuspiciousCall sc : suspicious) {
                    if (sc.methodName.equals(methodName)
                            && sc.receiverType.contains(receiverType)) {
                        sinks.add(new Sink(
                                "sink-llm-" + seq++,
                                category,
                                sc.receiverType + "." + sc.methodName,
                                sc.methodId,
                                sc.filePath,
                                sc.line,
                                sc.expression
                        ));
                    }
                }
            }
            return List.copyOf(sinks);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private String extractJsonArray(String rawOutput) {
        if (rawOutput == null) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(rawOutput.strip());
            if (root.isObject() && root.has("result")) {
                rawOutput = root.get("result").asText();
            }
        } catch (Exception ignored) {
        }
        Matcher fenced = FENCED_JSON.matcher(rawOutput);
        while (fenced.find()) {
            String body = fenced.group(1).strip();
            if (body.startsWith("[")) {
                return body;
            }
        }
        int start = rawOutput.indexOf('[');
        int end = rawOutput.lastIndexOf(']');
        if (start >= 0 && end > start) {
            return rawOutput.substring(start, end + 1);
        }
        return null;
    }

    private record SuspiciousCall(
            String methodName,
            String receiverType,
            String expression,
            String methodId,
            String filePath,
            int line
    ) { }

    private static final String PROMPT_TEMPLATE = """
            你是一个 Java 安全审计专家。以下调用点来自一个 Java 项目，它们调用了**外部依赖**中的方法（没有源码可查看）。
            请判断哪些是危险 sink（可被攻击者利用的安全敏感操作）。

            调用列表：
            %s

            只输出你认为是危险 sink 的条目，格式为 JSON 数组：
            [{"methodName": "方法名", "receiverType": "接收者类型关键字（小写）", "category": "类别"}]

            可用 category 值：%s

            不确定的不要输出。如果没有危险 sink，输出空数组 []。
            """;
}
