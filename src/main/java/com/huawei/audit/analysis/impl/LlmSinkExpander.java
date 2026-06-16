package com.huawei.audit.analysis.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huawei.audit.agent.ClaudeGateway;
import com.huawei.audit.analysis.impl.DangerousSinkClassifier.ExtraSinkRule;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class LlmSinkExpander {
    private static final Logger log = LoggerFactory.getLogger(
            LlmSinkExpander.class
    );
    private static final int MAX_DEPENDENCIES = 200;
    private static final int MAX_RULES = 200;
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

    List<ExtraSinkRule> expand(
            List<Map<String, String>> dependencies,
            ClaudeGateway claudeGateway,
            Path workingDirectory
    ) {
        if (dependencies == null || dependencies.isEmpty()
                || claudeGateway == null) {
            return List.of();
        }
        try {
            String depText = dependencyCoordinates(dependencies).stream()
                    .collect(Collectors.joining("\n"));
            if (depText.isBlank()) {
                return List.of();
            }
            String categories = String.join(", ", KNOWN_CATEGORIES);
            String prompt = PROMPT_TEMPLATE.formatted(depText, categories);
            return parseRules(claudeGateway.query(
                    workingDirectory,
                    prompt,
                    Duration.ofSeconds(60)
            ));
        } catch (RuntimeException exception) {
            log.warn(
                    "Unable to expand dependency sinks with Claude; "
                            + "continuing with built-in rules: {}",
                    exception.getMessage()
            );
            return List.of();
        }
    }

    private List<String> dependencyCoordinates(
            List<Map<String, String>> dependencies
    ) {
        Set<String> coordinates = new LinkedHashSet<>();
        for (Map<String, String> dependency : dependencies) {
            if (dependency == null) {
                continue;
            }
            String groupId = firstNonBlank(
                    dependency.get("group_id"),
                    dependency.get("groupId")
            );
            String artifactId = firstNonBlank(
                    dependency.get("artifact_id"),
                    dependency.get("artifactId")
            );
            if (groupId.isBlank() || artifactId.isBlank()) {
                continue;
            }
            String version = firstNonBlank(dependency.get("version"));
            String coordinate = groupId + ":" + artifactId;
            if (!version.isBlank()) {
                coordinate += ":" + version;
            }
            coordinates.add(coordinate);
            if (coordinates.size() == MAX_DEPENDENCIES) {
                break;
            }
        }
        return List.copyOf(coordinates);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.strip();
            }
        }
        return "";
    }

    private List<ExtraSinkRule> parseRules(String rawOutput) {
        try {
            String jsonArray = extractJsonArray(rawOutput);
            if (jsonArray == null) {
                return List.of();
            }
            List<Map<String, String>> items = objectMapper.readValue(
                    jsonArray, new TypeReference<>() {}
            );
            Set<ExtraSinkRule> rules = new LinkedHashSet<>();
            for (Map<String, String> item : items) {
                String methodName = item.getOrDefault("methodName", "").strip();
                String receiverType = item.getOrDefault("receiverType", "").strip()
                        .toLowerCase(Locale.ROOT);
                String category = item.getOrDefault("category", "")
                        .strip()
                        .toUpperCase(Locale.ROOT);
                if (methodName.isEmpty() || receiverType.isEmpty()
                        || !KNOWN_CATEGORIES.contains(category)) {
                    continue;
                }
                rules.add(new ExtraSinkRule(methodName, receiverType, category));
                if (rules.size() == MAX_RULES) {
                    break;
                }
            }
            return List.copyOf(rules);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    String extractJsonArray(String rawOutput) {
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

    private static final String PROMPT_TEMPLATE = """
            你是一个 Java 安全审计专家。下面是一个 Java 项目的依赖列表：\s

            %s

            已有的内置 sink 识别覆盖了标准库和主流框架（如 Runtime.exec、ProcessBuilder、
            ObjectInputStream.readObject、JdbcTemplate、DocumentBuilder.parse、
            SpEL/OGNL/Groovy/Freemarker/Velocity 表达式引擎等）。

            请分析上述依赖，找出其中可能包含但**未被内置规则覆盖**的危险 sink 方法。
            重点关注：
            - 冷门或企业内部 ORM/数据库框架的 SQL 执行方法
            - 非标准 HTTP 客户端的请求发送方法
            - 非标准序列化/反序列化库的解析方法
            - 脚本/表达式引擎的执行方法
            - 文件操作封装库的写入方法

            只输出 JSON 数组，不要任何解释文字。每个元素格式：
            {"methodName": "方法名（精确）", "receiverType": "接收者类型关键字（小写，用于包含匹配）", "category": "类别"}

            可用 category 值：%s

            如果没有需要补充的 sink，输出空数组 []。
            """;
}
